#!/usr/bin/env node
/*
 * node net-snmp peer adapter — a third independent SNMP stack.
 *
 * Same CLI/JSON contract as peer_pysnmp.py and peer_netsnmp.py (see
 * test/peers/README.md). This one is a JavaScript implementation with its
 * own BER encoder and its own USM (RFC 3414) crypto, which makes it a
 * genuinely independent check on our message encoding: gosnmp, net-snmp
 * and pysnmp all agreeing is good evidence, a fourth stack agreeing is
 * better.
 *
 * Verbs: get, getnext, getbulk, walk, set, trap, inform.
 *
 * Requires `npm install` in test/peers (test/peers/setup.sh).
 */

'use strict';

const path = require('path');
const snmp = require(path.join(__dirname, 'node_modules', 'net-snmp'));

const AUTH_PROTOCOLS = {
  md5: snmp.AuthProtocols.md5,
  sha: snmp.AuthProtocols.sha,
};

const PRIV_PROTOCOLS = {
  des: snmp.PrivProtocols.des,
  aes: snmp.PrivProtocols.aes,
};

function fail(kind, message, extra) {
  process.stdout.write(JSON.stringify(Object.assign({
    ok: false,
    error_kind: kind,
    error: message,
  }, extra || {})) + '\n');
  process.exit(0);
}

function parseArgs(argv) {
  const opts = {
    verb: argv[0],
    version: '2c',
    level: '',
    community: 'public',
    user: '',
    auth: '',
    priv: '',
    authProto: 'sha',
    privProto: 'aes',
    oids: [],
    varbinds: [],
    timeout: 3000,
    retries: 0,
    target: '',
    maxRepetitions: 10,
  };
  let i = 1;
  while (i < argv.length) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (value === undefined) fail('usage', `${flag} needs a value`);
    switch (flag) {
      case '--oid': opts.oids.push(value); break;
      case '--varbind': opts.varbinds.push(value); break;
      case '--target': opts.target = value; break;
      case '--version': opts.version = value; break;
      case '--level': opts.level = value; break;
      case '--community': opts.community = value; break;
      case '--user': opts.user = value; break;
      case '--auth': opts.auth = value; break;
      case '--priv': opts.priv = value; break;
      case '--auth-proto': opts.authProto = value; break;
      case '--priv-proto': opts.privProto = value; break;
      case '--timeout': opts.timeout = parseInt(value, 10); break;
      case '--retries': opts.retries = parseInt(value, 10); break;
      case '--max-repetitions': opts.maxRepetitions = parseInt(value, 10); break;
      default: fail('usage', `unknown flag ${flag}`);
    }
    i += 2;
  }
  if (!opts.target) fail('usage', '--target is required');
  return opts;
}

function splitTarget(target) {
  const idx = target.lastIndexOf(':');
  if (idx < 0) return [target, 161];
  return [target.slice(0, idx), parseInt(target.slice(idx + 1), 10)];
}

const LEVELS = {
  noauthnopriv: snmp.SecurityLevel.noAuthNoPriv,
  authnopriv: snmp.SecurityLevel.authNoPriv,
  authpriv: snmp.SecurityLevel.authPriv,
};

function buildSession(opts) {
  const [host, port] = splitTarget(opts.target);
  // net-snmp sends traps and informs to trapPort (default 162), while
  // requests go to port. Point both at the target or the trap silently
  // leaves for the local agent instead of the proxy.
  const base = { port, trapPort: port, timeout: opts.timeout, retries: opts.retries };
  if (opts.version !== '3') {
    const version = opts.version === '1' ? snmp.Version1 : snmp.Version2c;
    return snmp.createSession(host, opts.community, Object.assign({ version }, base));
  }
  const levelName = (opts.level
    || (opts.auth && opts.priv ? 'authpriv' : opts.auth ? 'authnopriv' : 'noauthnopriv')).toLowerCase();
  const level = LEVELS[levelName];
  if (level === undefined) fail('usage', `unknown security level ${levelName}`);
  const user = { name: opts.user, level };
  if (levelName !== 'noauthnopriv') {
    user.authProtocol = AUTH_PROTOCOLS[opts.authProto.toLowerCase()];
    user.authKey = opts.auth;
    if (user.authProtocol === undefined) fail('usage', `unknown auth protocol ${opts.authProto}`);
  }
  if (levelName === 'authpriv') {
    user.privProtocol = PRIV_PROTOCOLS[opts.privProto.toLowerCase()];
    user.privKey = opts.priv;
    if (user.privProtocol === undefined) fail('usage', `unknown priv protocol ${opts.privProto}`);
  }
  return snmp.createV3Session(host, user, base);
}

function parseVarbind(spec) {
  const eq = spec.indexOf('=');
  const oid = spec.slice(0, eq);
  const rest = spec.slice(eq + 1);
  const colon = rest.indexOf(':');
  const type = rest.slice(0, colon).toLowerCase();
  const value = rest.slice(colon + 1);
  const numeric = ['int', 'integer', 'gauge', 'counter32', 'counter64', 'timeticks', 'unsigned'];
  switch (type) {
    case 'string': case 'octetstring': return { oid, type: snmp.ObjectType.OctetString, value };
    case 'oid': return { oid, type: snmp.ObjectType.OID, value };
    case 'ipaddress': return { oid, type: snmp.ObjectType.IpAddress, value };
    default:
      if (numeric.includes(type)) {
        const map = {
          int: snmp.ObjectType.Integer, integer: snmp.ObjectType.Integer,
          gauge: snmp.ObjectType.Gauge32, counter32: snmp.ObjectType.Counter32,
          counter64: snmp.ObjectType.Counter64, timeticks: snmp.ObjectType.TimeTicks,
          unsigned: snmp.ObjectType.Gauge32,
        };
        return { oid, type: map[type], value: parseInt(value, 10) };
      }
      return fail('usage', `unknown varbind type ${type} in ${spec}`);
  }
}

const TYPE_NAMES = {
  2: 'Integer', 4: 'OctetString', 5: 'Null', 6: 'ObjectIdentifier',
  64: 'IpAddress', 65: 'Counter32', 66: 'Gauge32', 67: 'TimeTicks',
  70: 'Counter64', 128: 'NoSuchObject', 129: 'NoSuchInstance', 130: 'EndOfMibView',
};

function flatten(varbinds, out) {
  out = out || [];
  for (const vb of varbinds) {
    if (Array.isArray(vb)) flatten(vb, out);
    else out.push(vb);
  }
  return out;
}

function dump(varbinds) {
  // getBulk answers repeaters as one array per column; the contract is a
  // flat varbind list.
  return flatten(varbinds).map((vb) => ({
    oid: vb.oid,
    type: TYPE_NAMES[vb.type] || String(vb.type),
    value: Buffer.isBuffer(vb.value)
      ? vb.value.toString('utf8')
      : String(vb.value),
  }));
}

function classify(err) {
  // A PDU error-status arrives as RequestFailedError with .status set; it
  // is an ANSWER (notWritable, noSuchName, ...), not a transport error.
  if (err && err.status !== undefined) return 'status';
  const text = String((err.error || err.message || err)).toLowerCase();
  if (text.includes('timeout') || text.includes('timed out')) return 'timeout';
  if (text.includes('unsupported security level')) return 'security-level';
  if (text.includes('unknown user') || text.includes('authentication')) return 'auth';
  if (text.includes('decryption')) return 'decrypt';
  if (text.includes('not in time window')) return 'timeliness';
  if (text.includes('unknown engine')) return 'engine-discovery';
  return 'error';
}

function run(opts) {
  const session = buildSession(opts);
  const done = (err, varbinds) => {
    session.close();
    if (err) return fail(classify(err), String(err.error || err.message || err));
    if (!Array.isArray(varbinds)) varbinds = [];
    // An exception varbind (noSuchObject/noSuchInstance/endOfMibView) is a
    // VALUE, not an error: SNMPv2 answers "not here" that way, and a peer
    // that treats it as failure cannot take part in GETNEXT conformance.
    process.stdout.write(JSON.stringify({ ok: true, varbinds: dump(varbinds) }) + '\n');
  };

  switch (opts.verb) {
    case 'get': return session.get(opts.oids, done);
    case 'getnext': return session.getNext(opts.oids, done);
    case 'getbulk':
      return session.getBulk(opts.oids, 0, opts.maxRepetitions, done);
    case 'walk': {
      // subtree feeds once per response PDU; the contract is ONE JSON line
      // for the whole walk, so accumulate and print at the end.
      const walked = [];
      return session.subtree(opts.oids[0], 20, (varbinds) => {
        walked.push.apply(walked, varbinds);
      }, (err) => {
        session.close();
        if (err) return fail(classify(err), String(err.error || err.message || err));
        process.stdout.write(JSON.stringify({ ok: true, varbinds: dump(walked) }) + '\n');
      });
    }
    case 'set':
      if (!opts.varbinds.length) fail('usage', 'set needs --varbind oid=TYPE:value');
      return session.set(opts.varbinds.map(parseVarbind), done);
    case 'trap':
    case 'inform': {
      const oid = opts.oids[0] || '1.3.6.1.6.3.1.1.5.1';
      const vbs = opts.varbinds.map(parseVarbind);
      const cb = (err) => {
        session.close();
        if (err) fail(classify(err), String(err.error || err.message || err));
        process.stdout.write(JSON.stringify({ ok: true, varbinds: [] }) + '\n');
      };
      // For SNMPv1 net-snmp turns the trailing arc into specific-trap and
      // the rest into the enterprise OID, which is the RFC 2576 shape.
      return opts.verb === 'trap'
        ? session.trap(oid, vbs, cb)
        : session.inform(oid, vbs, cb);
    }
    default:
      return fail('usage', `unknown verb ${opts.verb}`);
  }
}

run(parseArgs(process.argv.slice(2)));
