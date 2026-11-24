const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const template = fs.readFileSync(path.join(__dirname, "..", "templates", "graph.html"), "utf8");
const start = template.indexOf("    function country_code_to_country_name(");
const end = template.indexOf("    // Fetch the analysis results from the server", start);
assert.ok(start !== -1 && end !== -1, "Graph script not found in template");

function graphFor(entries) {
    let graph;
    const container = {};
    const context = {
        document: {
            getElementById: () => container,
            body: { classList: { contains: () => false } },
            addEventListener: () => {},
        },
        vis: {
            DataSet: class {
                constructor(items) {
                    this.items = items;
                }
            },
            Network: class {
                constructor(_container, data) {
                    graph = data;
                }
                on() {}
            },
        },
    };
    vm.runInNewContext(template.slice(start, end), context);
    context.generateGraph(entries);
    return graph;
}

function hasEdge(graph, from, to, label) {
    return graph.edges.items.some((edge) => edge.from === from && edge.to === to && edge.label === label);
}

test("graphs Recorded Future ASN and VPN services for an IP without other providers or risk", () => {
    const ip = "192.0.2.1";
    const graph = graphFor([{
        observable: ip,
        type: "IPV4",
        recorded_future: {
            risk_score: 0,
            asn: "AS64500 Example",
            vpn_list: ["VPN One", "VPN Two", "VPN One"],
        },
    }]);

    assert.ok(hasEdge(graph, ip, "AS64500 Example", "ASN (recorded_future)"));
    assert.ok(hasEdge(graph, ip, "VPN One", "VPN Service (Recorded Future)"));
    assert.ok(hasEdge(graph, ip, "VPN Two", "VPN Service (Recorded Future)"));
    assert.equal(graph.edges.items.filter((edge) => edge.to === "VPN One").length, 1);
    assert.equal(graph.nodes.items.find((node) => node.id === "AS64500 Example").group, "asn");
    assert.equal(graph.nodes.items.find((node) => node.id === "VPN One").group, "vpn_service");
    assert.equal(graph.nodes.items.some((node) => node.id === "Recorded Future flagged"), false);
});

test("graphs IPv6 country and risk while sharing VPN nodes across IPs", () => {
    const ipv6 = "2001:db8::1";
    const ipv4 = "192.0.2.2";
    const graph = graphFor([
        {
            observable: ipv6,
            type: "IPV6",
            recorded_future: {
                asn: "AS64501",
                country: "United States",
                country_code: "us",
                vpn_list: ["VPN One"],
                risk_score: 40,
                rules: ["Example rule"],
            },
        },
        {
            observable: ipv4,
            type: "IPV4",
            recorded_future: { vpn_list: ["VPN One"], risk_score: 0 },
        },
    ]);

    assert.ok(hasEdge(graph, ipv6, "AS64501", "ASN (recorded_future)"));
    assert.ok(hasEdge(graph, ipv6, "United States", "Country (recorded_future)"));
    assert.ok(hasEdge(graph, ipv6, "VPN One", "VPN Service (Recorded Future)"));
    assert.ok(hasEdge(graph, ipv4, "VPN One", "VPN Service (Recorded Future)"));
    assert.equal(graph.nodes.items.filter((node) => node.id === "VPN One").length, 1);
    assert.ok(hasEdge(graph, ipv6, "Recorded Future flagged", "RF Risk: 40, Example rule"));
});

test("preserves other provider links and does not invent VPN links for domains or missing data", () => {
    const ip = "192.0.2.3";
    const domain = "example.com";
    const graph = graphFor([
        {
            observable: ip,
            type: "IPV4",
            ipinfo: { ip, asn: "AS64502", country_code: "us" },
            ipapi: { is_vpn: true, vpn: { service: "VPN One" } },
            recorded_future: { risk_score: 0, vpn_list: ["VPN One"] },
        },
        { observable: "192.0.2.4", type: "IPV4", recorded_future: { risk_score: 0 } },
        { observable: domain, type: "FQDN", recorded_future: { risk_score: 10, vpn_list: ["VPN Two"] } },
    ]);

    assert.ok(hasEdge(graph, ip, "AS64502", "ASN (ipinfo)"));
    assert.ok(hasEdge(graph, ip, "United States", "Country (ipinfo)"));
    assert.ok(hasEdge(graph, ip, "VPN One", "VPN Service (IPAPI)"));
    assert.ok(hasEdge(graph, ip, "VPN One", "VPN Service (Recorded Future)"));
    assert.equal(graph.nodes.items.filter((node) => node.id === "VPN One").length, 1);
    assert.ok(hasEdge(graph, domain, "Recorded Future flagged", "RF Risk: 10"));
    assert.equal(graph.nodes.items.some((node) => node.id === "VPN Two"), false);
    assert.equal(graph.edges.items.filter((edge) => edge.label === "VPN Service (Recorded Future)").length, 1);
});

test("graphs each returned risk rule and threat list for every associated observable", () => {
    const domain = "example.com";
    const ip = "192.0.2.5";
    const rules = [
        "Recently Detected Malware Operation",
        "Recently Suspected Phishing Techniques",
        "Historically Detected Malware Operation",
    ];
    const graph = graphFor([
        {
            observable: domain,
            type: "FQDN",
            recorded_future: {
                risk_score: 72,
                rules: [...rules, rules[0]],
                threat_lists: ["Malware Infrastructure", "Malware Infrastructure"],
            },
        },
        {
            observable: ip,
            type: "IPV4",
            recorded_future: { risk_score: 0, rules: [rules[0]], threat_lists: ["Malware Infrastructure"] },
        },
    ]);

    for (const rule of rules) {
        const nodeId = `recorded_future_rule:${rule}`;
        assert.ok(hasEdge(graph, domain, nodeId, "Risk Rule (Recorded Future)"));
        assert.equal(graph.nodes.items.find((node) => node.id === nodeId).label, rule);
    }
    assert.ok(hasEdge(graph, ip, `recorded_future_rule:${rules[0]}`, "Risk Rule (Recorded Future)"));
    assert.equal(graph.nodes.items.filter((node) => node.id === `recorded_future_rule:${rules[0]}`).length, 1);
    assert.equal(graph.edges.items.filter((edge) => edge.from === domain && edge.to === `recorded_future_rule:${rules[0]}`).length, 1);
    for (const observable of [domain, ip]) {
        assert.ok(hasEdge(graph, observable, "recorded_future_threat_list:Malware Infrastructure", "Threat List (Recorded Future)"));
    }
    assert.equal(graph.nodes.items.filter((node) => node.id === "recorded_future_threat_list:Malware Infrastructure").length, 1);
    assert.ok(hasEdge(graph, domain, "Recorded Future flagged", `RF Risk: 72, ${rules[0]}`));
});

test("does not create risk rule or threat list nodes for missing or empty data", () => {
    const graph = graphFor([
        { observable: "example.com", type: "FQDN", recorded_future: { risk_score: 0, rules: [], threat_lists: [] } },
        { observable: "192.0.2.6", type: "IPV4", recorded_future: { risk_score: 0 } },
    ]);

    assert.equal(graph.nodes.items.some((node) => node.group === "recorded_future_rule"), false);
    assert.equal(graph.nodes.items.some((node) => node.group === "recorded_future_threat_list"), false);
});
