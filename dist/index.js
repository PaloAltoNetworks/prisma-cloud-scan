/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 320:
/***/ ((module) => {

module.exports = eval("require")("@actions/core");


/***/ }),

/***/ 219:
/***/ ((module) => {

module.exports = eval("require")("@actions/exec");


/***/ }),

/***/ 636:
/***/ ((module) => {

module.exports = eval("require")("@actions/tool-cache");


/***/ }),

/***/ 383:
/***/ ((module) => {

module.exports = eval("require")("axios");


/***/ }),

/***/ 147:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 37:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
const fs = __nccwpck_require__(147);
const axios = __nccwpck_require__(383);
const core = __nccwpck_require__(320);
const { exec } = __nccwpck_require__(219);
const tc = __nccwpck_require__(636);
const os = __nccwpck_require__(37);

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
async function getTwistcli(version, url, authToken, platform, architecture) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    console.log(`Invalid Console address: ${url}`);
    process.exit(1);
  }
  let endpointPrefix = '';
  let endpointValue = 'twistcli';
  
  if(platform === 'win32') {
    endpointPrefix = 'windows/';
    endpointValue = 'twistcli.exe';
  } else if(platform === 'darwin') {
    endpointPrefix = 'osx/';
    if (architecture === 'arm64') endpointPrefix += 'arm64/';
  } else if(platform === 'linux') {
    if (architecture === 'arm64') endpointPrefix += 'arm64/';
  }

  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, '/api/v1/util/' + endpointPrefix + endpointValue);

  let twistcli = tc.find('twistcli', version);
  if (!twistcli) {
    const twistcliPath = await tc.downloadTool(parsedUrl.toString(), undefined, `Bearer ${authToken}`);
    if (platform !== 'win32') await exec(`chmod a+x ${twistcliPath}`);
    twistcli = await tc.cacheFile(twistcliPath, endpointValue, 'twistcli', version);
  }
  core.addPath(twistcli);

  return endpointValue;
}

function formatSarifToolDriverRules(results) {
  // Only 1 image can be scanned at a time
  const result = results[0];
  const vulnerabilities = result.vulnerabilities;
  const compliances = result.compliances;

  const vulnerabilitiesFiltered = (vulnerabilities || []).filter(
    (thing, index, self) =>
      index ===
      self.findIndex((t) => t.id === thing.id )
  ); 


  let vulns = [];
  if (vulnerabilitiesFiltered) {
    vulns = vulnerabilitiesFiltered.map(vuln => {
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

/**
 * convert prima severity to github severity
 * @param {string} severity
 * @throws {Error} unknown severity
 * @returns string
 */
function convertPrismaSeverity(severity) {
  // prisma: critical, high, important, medium, moderate, unimportant, low
  // gh: error, warning, note, none
  switch (severity) {
    case "critical":
      return "error";
    case "high":
      return "warning";
    case "important":
      return "warning";
    case "medium":
      return "note";
    case "moderate":
      return "note";
    case "low":
      return "none";
    case "unimportant":
      return "none";
    default:
      throw new Error(`Unknown severity: ${severity}`);
  }
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
        level: `${convertPrismaSeverity(finding.severity)}`,
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
  const project = core.getInput('project');

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

    let twistcliCmd = await getTwistcli(twistcliVersion, consoleUrl, token, os.platform(), os.arch());
    twistcliCmd = [twistcliCmd];
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
    if (project) {
      twistcliCmd = twistcliCmd.concat([`--project ${project}`]);
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

if (require.main === require.cache[eval('__filename')]) {
  try {
    scan();
  } catch (err) {
    core.setFailed(err.message);
  }
}

})();

module.exports = __webpack_exports__;
/******/ })()
;