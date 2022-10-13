const fs = require('fs');
const axios = require('axios').default;
const core = require('@actions/core');
const { exec } = require('@actions/exec');
const tc = require('@actions/tool-cache');

const TRUE_VALUES = ['true', 'yes', 'y', '1'];

function toSentenceCase(string) {
  return string[0].toUpperCase() + string.slice(1).toLowerCase();
}

// https://github.com/nodejs/node/issues/18288#issuecomment-475864601
// Necessary for Console URLs that already have a path (all SaaS Consoles)
function joinUrlPath(...parts) {
  // Filter handles cases where Console URL pathname is '/' in order to avoid '//api/v1/etc/' (double slash)
  return '/' + parts.filter(part => part !== '/').map(part => part.replace(/(^\/|\/$)/g, '')).join('/');
}

// Wrapper around 'authenticate' Console API endpoint
async function authenticate(url, user, pass) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    console.log(`Invalid Console address: ${url}`);
    process.exit(1);
  }
  const endpoint = '/api/v1/authenticate';
  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, endpoint);

  try {
    const res = await axios({
      method: 'post',
      url: parsedUrl.toString(),
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        username: user,
        password: pass,
      },
    });
    return res.data.token;
  } catch (err) {
    core.setFailed(`Failed getting authentication token: ${err.message}`);
    process.exit(1);
  }
}

// Wrapper around 'version' Console API endpoint
async function getVersion(url, token) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    console.log(`Invalid Console address: ${url}`);
    process.exit(1);
  }
  const endpoint = '/api/v1/version';
  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, endpoint);

  try {
    const res = await axios({
      method: 'get',
      url: parsedUrl.toString(),
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    return res.data;
  } catch (err) {
    core.setFailed(`Failed getting version: ${err.message}`);
    process.exit(1);
  }
}

// GitHub Action-specific wrapper around 'util/twistcli' Console API endpoint
// Saves twistcli using GitHub Action's tool-cache library
async function getTwistcli(version, url, authToken) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    console.log(`Invalid Console address: ${url}`);
    process.exit(1);
  }
  const endpoint = '/api/v1/util/twistcli';
  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, endpoint);

  let twistcli = tc.find('twistcli', version);
  if (!twistcli) {
    const twistcliPath = await tc.downloadTool(parsedUrl.toString(), undefined, `Bearer ${authToken}`);
    await exec(`chmod a+x ${twistcliPath}`);
    twistcli = await tc.cacheFile(twistcliPath, 'twistcli', 'twistcli', version);
  }
  core.addPath(twistcli);
}

function formatSarifToolDriverRules(results) {
  // Only 1 image can be scanned at a time
  const result = results[0];
  const vulnerabilities = result.vulnerabilities;
  const compliances = result.compliances;

  let vulns = [];
  if (vulnerabilities) {
    vulns = vulnerabilities.map(vuln => {
      return {
        id: `${vuln.id}`,
        shortDescription: {
          text: `[Prisma Cloud] ${vuln.id} in ${vuln.packageName} (${vuln.severity})`,
        },
        fullDescription: {
          text: `${toSentenceCase(vuln.severity)} severity ${vuln.id} found in ${vuln.packageName} version ${vuln.packageVersion}`,
        },
        help: {
          text: '',
          markdown: '| CVE | Severity | CVSS | Package | Version | Fix Status | Published | Discovered |\n' +
            '| --- | --- | --- | --- | --- | --- | --- | --- |\n' +
            '| [' + vuln.id + '](' + vuln.link + ') | ' + vuln.severity + ' | ' + (vuln.cvss || 'N/A') + ' | ' + vuln.packageName + ' | ' + vuln.packageVersion + ' | ' + (vuln.status || 'not fixed') + ' | ' + vuln.publishedDate + ' | ' + vuln.discoveredDate + ' |',
        },
      };
    });
  }

  let comps = [];
  if (compliances) {
    comps = compliances.map(comp => {
      return {
        id: `${comp.id}`,
        shortDescription: {
          text: `[Prisma Cloud] Compliance check ${comp.id} violated (${comp.severity})`,
        },
        fullDescription: {
          text: `${toSentenceCase(comp.severity)} severity compliance check "${comp.title}" violated`,
        },
        help: {
          text: '',
          markdown: '| Compliance Check | Severity | Title |\n' +
            '| --- | --- | --- |\n' +
            '| ' + comp.id + ' | ' + comp.severity + ' | ' + comp.title + ' |',
        },
      };
    });
  }

  return [...vulns, ...comps];
}

function formatSarifResults(results) {
  // Only 1 image can be scanned at a time
  const result = results[0];
  const imageName = result.name;
  let findings = [];
  if (result.vulnerabilities) {
    findings = [...findings, ...result.vulnerabilities];
  }
  if (result.compliances) {
    findings = [...findings, ...result.compliances];
  }

  if (findings) {
    return findings.map(finding => {
      return {
        ruleId: `${finding.id}`,
        level: 'warning',
        message: {
          text: `Description:\n${finding.description}`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: `${imageName}`,
            },
            region: {
              startLine: 1,
              startColumn: 1,
              endLine: 1,
              endColumn: 1,
            },
          },
        }],
      };
    });
  }

  return [];
}

function formatSarif(twistcliVersion, resultsFile) {
  try {
    const scan = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Prisma Cloud (twistcli)',
            version: `${twistcliVersion}`,
            rules: formatSarifToolDriverRules(scan.results),
          },
        },
        results: formatSarifResults(scan.results),
      }],
    };
    return sarif;
  } catch (err) {
    core.setFailed(`Failed formatting SARIF: ${err.message}`);
    process.exit(1);
  }
}

async function scan() {
  const httpProxy = process.env.https_proxy || process.env.HTTPS_PROXY || process.env.http_proxy || process.env.HTTP_PROXY;
  const consoleUrl = core.getInput('pcc_console_url');
  const username = core.getInput('pcc_user');
  const password = core.getInput('pcc_pass');
  const imageName = core.getInput('image_name');
  const containerized = core.getInput('containerized').toLowerCase();
  const dockerAddress = core.getInput('docker_address') || process.env.DOCKER_ADDRESS || process.env.DOCKER_HOST;
  const dockerTlsCaCert = core.getInput('docker_tlscacert');
  const dockerTlsCert = core.getInput('docker_tlscert');
  const dockerTlsKey = core.getInput('docker_tlskey');

  const resultsFile = core.getInput('results_file');
  const sarifFile = core.getInput('sarif_file');

  try {
    let token;
    try {
      token = await authenticate(consoleUrl, username, password, httpProxy);
    } catch (err) {
      core.setFailed(`Failed authenticating: ${err.message}`);
      process.exit(1);
    }

    let twistcliVersion;
    try {
      twistcliVersion = await getVersion(consoleUrl, token, httpProxy);
    } catch (err) {
      core.setFailed(`Failed getting version: ${err.message}`);
      process.exit(1);
    }
    twistcliVersion = twistcliVersion.replace(/"/g, '');

    await getTwistcli(twistcliVersion, consoleUrl, token);
    let twistcliCmd = ['twistcli'];
    if (httpProxy) {
      twistcliCmd = twistcliCmd.concat([`--http-proxy ${httpProxy}`]);
    }
    twistcliCmd = twistcliCmd.concat([
      'images', 'scan',
      `--address ${consoleUrl}`,
      `--user ${username}`, `--password ${password}`,
      `--output-file ${resultsFile}`,
      '--details',
    ]);
    if (dockerAddress) {
      twistcliCmd = twistcliCmd.concat([`--docker-address ${dockerAddress}`]);
    }
    if (dockerTlsCaCert) {
      twistcliCmd = twistcliCmd.concat([`--docker-tlscacert ${dockerTlsCaCert}`]);
    }
    if (dockerTlsCert) {
      twistcliCmd = twistcliCmd.concat([`--docker-tlscert ${dockerTlsCert}`]);
    }
    if (dockerTlsKey) {
      twistcliCmd = twistcliCmd.concat([`--docker-tlskey ${dockerTlsKey}`]);
    }
    if (TRUE_VALUES.includes(containerized)) {
      twistcliCmd = twistcliCmd.concat(['--containerized']);
    }
    twistcliCmd = twistcliCmd.concat([imageName]);

    const exitCode = await exec(twistcliCmd.join(' '), undefined, {
      ignoreReturnCode: true,
    });
    if (exitCode > 0) {
      core.setFailed('Image scan failed');
    }

    fs.writeFileSync(sarifFile, JSON.stringify(formatSarif(twistcliVersion, resultsFile)));

    core.setOutput('results_file', resultsFile);
    core.setOutput('sarif_file', sarifFile);
  } catch (err) {
    core.setFailed(`Image scan failed: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  try {
    scan();
  } catch (err) {
    core.setFailed(err.message);
  }
}
