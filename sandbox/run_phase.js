// 一次沙箱阶段（npm 生态），在隔离容器里跑：离线装一个版本的包，跑攻击脚本和冒烟测试，打印 JSON 裁决。
// 由编排器每次修复调两次：一次装在用版本，一次装修复版本。全程 docker run --network none。
// env: PKG, VERSION, ATTACK（/verify 下的文件）, TEST（可选）
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const VENDOR = '/opt/vendor';
const VERIFY = '/verify';
const work = fs.mkdtempSync('/tmp/phase-');

function verdict(out) {
  const lines = (out || '').split('\n').map((s) => s.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const head = lines[i].split(' ')[0];
    if (head === 'EXPLOITED' || head === 'BLOCKED') return head;
  }
  return 'ERROR';
}

function run(cmd, args) {
  try {
    const out = execFileSync(cmd, args, { cwd: work, timeout: 180000, stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, out: out.toString() };
  } catch (e) {
    return { code: e.status || 1, out: ((e.stdout || '') + (e.stderr || '')).toString() };
  }
}

const pkg = process.env.PKG;
const version = process.env.VERSION;
const tgz = path.join(VENDOR, `${pkg}-${version}.tgz`);
const target = fs.existsSync(tgz) ? tgz : `${pkg}@${version}`;

fs.writeFileSync(path.join(work, 'package.json'), '{"name":"sb","private":true}');
const res = {};
const inst = run('npm', ['i', '--offline', '--no-audit', '--no-fund', '--silent', target]);
if (inst.code) {
  console.log(JSON.stringify({ install: 'fail', detail: inst.out.slice(-300) }));
  process.exit(0);
}
res.install = version;
// 脚本要和 node_modules 放在一起，node 才按这里解析 require
function stage(name) {
  const dst = path.join(work, name);
  fs.copyFileSync(path.join(VERIFY, name), dst);
  return dst;
}
const atk = run('node', [stage(process.env.ATTACK)]);
res.attack = verdict(atk.out);
res.attack_raw = atk.out.trim().slice(-200);
if (process.env.TEST) {
  const t = run('node', [stage(process.env.TEST)]);
  res.test = t.code === 0 ? 'pass' : 'fail';
}
console.log(JSON.stringify(res));
