const fetch = require('node-fetch')
const core = require('@actions/core')
const tc = require('@actions/tool-cache')
const { exec } = require('@actions/exec')

// https://github.com/nodejs/node/issues/18288#issuecomment-475864601
// Necessary for Console URLs that already have a path (all SaaS Consoles)
function joinUrlPath(...parts) {
  // Filter handles cases where Console URL pathname is '/' in order to avoid '//api/v1/etc/' (double slash)
  return '/' + parts.filter(part => part !== '/').map(part => part.replace(/(^\/|\/$)/g, '')).join('/');
}

// Wrapper around 'authenticate' Console API endpoint
async function getToken (addr, user, pass) {
  const authEndpoint = '/api/v1/authenticate'
  let authUrl
  try {
    authUrl = new URL(addr)
  } catch (err) {
    core.setFailed(`Invalid Console address: ${addr}`)
  }
  authUrl.pathname = joinUrlPath(authUrl.pathname, authEndpoint)
  try {
    const authResponse = await fetch(authUrl.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: user,
        password: pass
      })
    })
    const responseJson = await authResponse.json()

    return responseJson.token
  } catch (err) {
    core.setFailed(`Failed getting authentication token: ${err.message}`)
  }
}

// Wrapper around 'version' Console API endpoint
async function getVersion (addr, authToken) {
  const versionEndpoint = '/api/v1/version'
  let versionUrl 
  try {
    versionUrl = new URL(addr)
  } catch (err) {
    core.setFailed(`Invalid Console address: ${addr}`)
  }
  versionUrl.pathname = joinUrlPath(versionUrl.pathname, versionEndpoint)
  try {
    const versionResponse = await fetch(versionUrl.toString(), {
      headers: {
        Authorization: `Bearer ${authToken}`
      }
    })
    const responseText = await versionResponse.text()

    return responseText
  } catch (err) {
    core.setFailed(`getVersion: ${err.message}`)
  }
}

// GitHub Action-specific wrapper around 'util/twistcli' Console API endpoint
// Saves twistcli using GitHub Action's tool-cache library
async function getTwistcli (addr, authToken) {
  const twistcliEndpoint = '/api/v1/util/twistcli'
  let twistcliUrl
  try {
    twistcliUrl = new URL(addr)
  } catch (err) {
    core.setFailed(`Invalid Console address: ${addr}`)
  }
  twistcliUrl.pathname = joinUrlPath(twistcliUrl.pathname, twistcliEndpoint)

  let version
  try {
    version = await getVersion(addr, authToken)
  } catch (err) {
    core.setFailed(`Failed getting version: ${err.message}`)
  }
  version = version.replace(/"/g, '')  

  let twistcli = tc.find('twistcli', version)
  if (!twistcli) {
    const twistcliPath = await tc.downloadTool(twistcliUrl.toString(), undefined, `Bearer ${authToken}`)
    await exec(`chmod a+x ${twistcliPath}`)
    twistcli = await tc.cacheFile(twistcliPath, 'twistcli', 'twistcli', version)
  }

  core.addPath(twistcli)
}

async function scan () {
  // User inputs
  const consoleUrl = core.getInput('pcc_console_url')
  const username = core.getInput('pcc_user')
  const password = core.getInput('pcc_pass')
  const imageName = core.getInput('image_name')
  const resultsFile = core.getInput('results_file')
  try {
    const token = await getToken(consoleUrl, username, password)
    await getTwistcli(consoleUrl, token)
    const twistcliCmd = [
      'twistcli', 'images', 'scan',
      `--address ${consoleUrl}`,
      `--user ${username}`, `--password ${password}`,
      `--output-file ${resultsFile}`,
      '--details', imageName
    ]

    const exitCode = await exec(twistcliCmd.join(' '), undefined, {
      ignoreReturnCode: true
    })
    if (exitCode > 0) {
      core.setFailed('twistcli scan failed')
    }
    core.setOutput('results_file', resultsFile)
  } catch (err) {
    core.setFailed(`Image scan failed: ${err.message}`)
  }
}

if (require.main === module) {
  try {
    scan()
  } catch (err) {
    core.setFailed(err.message)
  }
}
