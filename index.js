var spawn = require('child_process').spawn;
var lazy = require('lazy');

exports.allow = function (rule) {
    rule.target = 'ACCEPT';
    if (!rule.action) { rule.action = '-A'; }
    newRule(rule);
}

exports.drop = function (rule) {
    rule.target = 'DROP';
    if (!rule.action) { rule.action = '-A'; }
    newRule(rule);
}

exports.reject = function (rule) {
    rule.target = 'REJECT';
    if (!rule.action) { rule.action = '-A'; }
    newRule(rule);
}

exports.list = function(table, chain, cb) {
    // Accepts optional table argument
    if(!cb) {
        cb = chain;
        chain = table;
        table = undefined;
    }
    var rule = {
        list : true,
        chain : chain,
                table : table,
        action : '-L',
        sudo : true
    };

    lazy(iptables(rule).stdout)
        .lines
        .map(String)
        .skip(2)
        .map(function (line) {
            // packets, bytes, target, pro, opt, in, out, src, dst, opts
            var fields = line.trim().split(/\s+/, 9);
            return {
                parsed : {
                    packets : fields[0],
                    bytes : fields[1],
                    target : fields[2],
                    protocol : fields[3],
                    opt : fields[4],
                    in : fields[5],
                    out : fields[6],
                    src : fields[7],
                    dst : fields[8]
                },
                raw : line.trim()
            };
        })
        .join(function (rules) {
            cb(rules);
        })
}

exports.newRule = newRule;
exports.deleteRule = deleteRule;

function iptables (rule) {
    var args = iptablesArgs(rule);

    var cmd = 'iptables';
    if (rule.sudo) {
        cmd = 'sudo';
        args = ['iptables'].concat(args);
    }

    console.log('Running command', cmd, args.join(' '));

    var proc = spawn(cmd, args);
    proc.stderr.on('data', function (buf) {
        console.error(buf.toString());
    });
    return proc;
}

function iptablesArgs (rule) {
    var args = [];

    if (!rule.table) { rule.table = 'filter'; }
    if (!rule.chain) { rule.chain = 'INPUT'; }

    if (rule.table) { args = args.concat(['-t', rule.table]); }
    if (rule.action) { args.push(rule.action); }
    if (rule.policy) { args.push('--policy'); }
    if (rule.chain) { args = args.concat([rule.chain]); }
    if (rule.policy) { args.push(rule.policy); }
    if (rule.protocol) { args = args.concat(['-p', rule.protocol]); }
    if (rule.src) { args = args.concat(['--src', rule.src]); }
    if (rule.dst) { args = args.concat(['--dst', rule.dst]); }
    if (rule.sport) { args = args.concat(['--sport', rule.sport]); }
    if (rule.dport) { args = args.concat(['--dport', rule.dport]); }
    if (rule.in) { args = args.concat(['-i', rule.in]); }
    if (rule.out) { args = args.concat(['-o', rule.out]); }
    if (rule.state) { args = args.concat(['-m', 'state', '--state', rule.state]); }
    if (rule.target) { args = args.concat(['-j', rule.target]); }
    if (rule.list) { args = args.concat(['-n', '-v']); }
    if (rule.to) { args = args.concat(['--to', rule.to]); }

    return args;
}

function newRule (rule) {
    return new Promise(function(resolve) {
        var proc = iptables(rule);
        proc.on('close', resolve);
    });
}

function deleteRule (rule) {
    rule.action = '-D';
    iptables(rule);
}

