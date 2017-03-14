#!/usr/bin/env node
var args = process.argv.slice(2)
var path = require('path')
var fs = require('fs')
var private = false
var description = ''
var opener = require('opener')
var copy = process.platform === 'darwin'
var open = true
var stdin = true
var anon = false
var type = 'txt'
var files = []
var doMain = true
var ini = require('ini')
var child_process = require('child_process')
var execFile = child_process.execFile
var spawn = child_process.spawn
var home = require('osenv').home()
var authFile = home + '/.gist-login'
var https = require('https')
var read = require('read')
var userAgent = 'node/gist-cli@' + require('./package.json').version
var argUN = null
var argPW = null
var edit = false
var prune = false
var url = require('url')

var debug
if (process.env.NODE_DEBUG && /\bgist\b/.exec(process.env.NODE_DEBUG)) {
  var util = require('util')
  debug = function() {
    var m = util.format.apply(util, arguments)
    console.error('GIST', m)
  }
} else {
  debug = function() {}
}

for (var a = 0; a < args.length; a++) {
  switch (args[a]) {
    case '-e': case '--edit':
      edit = args[++a]
      var p = url.parse(edit || '')
      if (p && p.host)
        edit = p.pathname
      edit = path.basename(edit)
      break
    case '--prune':
      prune = true
      break
    case '-u': case '--user': case '--username':
      argUN = args[++a]
      break
    case '-P': case '--pass': case '--password':
      argPW = args[++a]
      break
    case '-c': case '--copy':
      copy = process.platform === 'darwin'
      break
    case '--no-copy':
      copy = false
      break
    case '-p': case '--private':
      private = true
      break
    case '--no-private':
      private = false
      break
    case '-t': case '--type':
      type = args[++a]
      break
    case '-d': case '--description':
      description = args[++a]
      break
    case '-o': case '--open':
      open = true
      break
    case '--no-open':
      open = false
      break
    case '-v': case '--version':
      version()
      doMain = false
      break
    case '-h': case '--help':
      help()
      doMain = false
      break
    case '-a': case '--anon': case '--anonymous':
      anon = true
      break
    default:
      files.push(args[a])
      break
  }
}

if (files.length !== 0 && files.indexOf('-') === -1)
  stdin = false

if (doMain) main()


function help() {
  console.log([
    'Usage: gist [options] [filename, ...]',
    'Filename \'-\' forces gist to read from stdin.',
    'gist will read from stdin by default if no files specified',
    '    -p, --[no-]private               Make the gist private',
    '    -t, --type [EXTENSION]           Set syntax highlighting of the Gist by file extension',
    '                                     (Only applies to stdin data, filenames use extension)',
    '    -d, --description DESCRIPTION    Set description of the new gist',
    '    -o, --[no-]open                  Open gist in browser',
    '    -c, --[no-]copy                  Save url to clipboard (osx only)',
    '    -v, --version                    Print version',
    '    -h, --help                       Display this screen'
  ].join('\n'))
}

function version() {
  console.log(require('./package.json').version)
}

function main() {
  debug('main start')
  if (anon && private) {
    console.error('Cannot create private anonymous gists')
    process.exit(1)
  }

  if (prune && !edit) {
    console.error('--prune requires a --edit argument')
    process.exit(1)
  }

  if (anon)
    getData(files, onData.bind(null, null))
  else
    getAuth(function(er, auth) {
      debug('auth', er, auth)
      if (er)
        throw er
      getData(files, onData.bind(null, auth))
    })
}

function onData(auth, er, data) {
  if (er)
    throw er

  var body = {
    description: description,
    public: !private && !anon,
    files: data.files
  }

  if (data.edit) {
    body.description = description || data.edit.description
    body.public = data.edit.public
    if (prune) {
      for (var f in data.edit.files) {
        if (!body.files[f])
          body.files[f] = null
      }
    }
  }

  body = new Buffer(JSON.stringify(body))

  debug('body', body.toString())

  var opt = {
    method: edit ? 'PATCH' : 'POST',
    host: 'api.github.com',
    port: 443,
    path: '/gists' + (edit ? '/' + edit : ''),
    headers: {
      host: 'api.github.com',
      'user-agent': userAgent,
      'content-length': body.length,
      'content-type': 'application/json'
    }
  }

  if (!anon)
    opt.headers.authorization = 'token ' + auth.token

  debug('making request', opt)
  var req = https.request(opt)
  req.on('response', function (res) {
    var result = ''
    res.setEncoding('utf8')
    res.on('data', function(c) {
      result += c
    })
    res.on('end', function() {
      result = JSON.parse(result)
      debug('result', result)
      var id = result.id
      var user = auth && auth.user || 'anonymous'
      var url = 'https://gist.github.com/' + user + '/' + id
      if (open)
        opener(url)
      if (copy)
        copyUrl(url)
      process.on('exit', function() {
        console.log(url)
      })
    })

    if (auth) {
      saveAuth(auth, function (er, result) {
        if (er)
          throw er
      })
    }
  })
  req.end(body)
}

function copyUrl(url) {
  spawn('pbcopy', []).stdin.end(url)
}

function getAuth(cb) {
  var user = argUN
  var pass = argPW
  var argAuth = { user: argUN, pass: argPW }
  if (user && pass) {
    debug('auth on argv')
    return tokenize({ user: argUN, pass: argPW }, cb)
  }

  if (user && !pass) {
    debug('user on argv, password required')
    return getPassFromCli(argAuth, function (er, auth) {
      debug('getPassFromCli', er, auth)
      done(er, auth)
    })
  }

  getAuthFromFile(authFile, function(er, auth) {
    debug('getAuthFromFile', er, auth)
    if (er)
      getAuthFromGit(function (er, auth) {
        debug('getAuthFromGit', er, auth)
        if (er)
          getAuthFromCli(function (er, auth) {
            debug('getAuthFromCli', er, auth)
            done(er, auth)
          })
        else
          done(er, auth)
      })
    else
      done(er, auth)
  })

  function done(er, auth) {
    if (er)
      return cb(er)
    auth.user = auth.user.trim()
    auth.token = auth.token.trim()
    if (argAuth.user && auth.user !== argAuth.user) {
      auth.user = argAuth.user
      delete auth.token
      auth.pass = argAuth.pass
    }
    cb(er, auth)
  }
}

function getAuthFromCli(cb) {
  // can't read a file from stdin if we're reading login!
  if (files.indexOf('-') !== -1 || stdin) {
    debug('error: gisting stdin and also reading auth on stdin')
    process.exit(1)
  }

  var data = {}
  read({ prompt: 'github.com username: ' }, function(er, user) {
    if (er)
      return cb(er)
    data.user = user.trim()
    getPassFromCli(data, cb)
  })
}

function getPassFromCli(data, cb) {
  if (files.indexOf('-') !== -1 || stdin) {
    debug('error: gisting stdin and also reading auth on stdin')
    process.exit(1)
  }

  read({ prompt: 'github.com password: ', silent: true }, function(er, password) {
    if (er)
      return cb(er)
    password = password.trim()
    data.pass = password
    tokenize(data, cb)
  })
}

function tokenize (data, cb) {
  // curl -u isaacs \
  //   -d '{"scopes":["gist"],"note":"gist cli access"}' \
  //   https://api.github.com/authorizations
  var body = new Buffer(JSON.stringify({
    scopes: [ 'gist' ],
    note: 'gist cli access'
  }))
  var r = {
    method: 'POST',
    host: 'api.github.com',
    headers: {
      'content-type': 'application/json',
      'content-length': body.length,
      'user-agent': userAgent,
      authorization: 'Basic ' +
        new Buffer(data.user + ':' + data.pass).toString('base64')
    },
    path: '/authorizations'
  }

  if (data.otp)
    r.headers['X-GitHub-OTP'] = data.otp

  var req = https.request(r)
  var result = ''
  req.on('response', function(res) {
    res.on('error', cb)
    res.setEncoding('utf8')
    res.on('data', function(c) {
      result += c
    })
    res.on('end', function() {
      result = JSON.parse(result)
      if (res.statusCode >= 400) {
        debug('failed', res.statusCode, result)
        var otp = res.headers['x-github-otp']
        if (res.statusCode === 401 &&
            !data.otp && otp && otp.match(/^required; /)) {
          var type = otp.replace(/^required; /, '')
          return getOTP(data, type, cb)
        }
        var message = result.message || JSON.stringify(result)
        return cb(new Error(message))
      }
      debug('ok', res.statusCode, result)
      data.token = result.token
      // just to make sure we don't waste this...
      if (files.length === 0)
        saveAuth(data, function(er) {
          cb(er, data)
        })
      else
        cb(null, data)
    })
  })
  req.on('error', cb)
  req.write(body)
  req.end()
}

function getOTP(data, type, cb) {
  if (files.indexOf('-') !== -1 || stdin) {
    debug('error: gisting stdin and also reading auth on stdin')
    process.exit(1)
  }

  read({
    prompt: 'two factor auth (' + type + '): ',
    silent: true
  }, function(er, otp) {
    if (er)
      return cb(er)
    data.otp = otp.trim()
    tokenize(data, cb)
  })
}

function getAuthFromFile(authFile, cb) {
  // try to load from our file
  fs.readFile(authFile, 'utf8', function(er, data) {
    if (er)
      return cb(er)
    data = ini.parse(data)
    if (!data.gist || !data.gist.user || !data.gist.token)
      return cb(new Error('no login data in '+authFile))
    return cb(null, data.gist)
  })
}

function getAuthFromGit(cb) {
  var data = {}
  getConfFromGit('gist.user', function(er, user) {
    if (er)
      return cb(er)
    data.user = user
    getConfFromGit('gist.token', function(er, token) {
      if (er)
        return cb(er)
      data.token = token
      cb(null, data)
    })
  })
}

function getConfFromGit(key, cb) {
  debug('getConfFromGit', 'git', ['config', '--get', key].join(' '))
  var env = { env: process.env }
  execFile('git', ['config', '--get', key], env, function (er, stdout, stderr) {
    debug('back from git config', er, stdout, stderr)
    if (er || !stdout)
      debug(stderr)
    return cb(er, stdout)
  })
}

function saveAuth(data, cb) {
  var d = { gist: {
    user: data.user,
    token: data.token
  }}
  fs.writeFile(authFile, ini.stringify(d), cb)
}

function getData(files, cb) {
  var data = { files: {} }
  if (stdin && files.indexOf('-') === -1)
    files.push('-')

  var c = files.length
  if (edit) {
    c++
    getEditData(function(er, editData) {
      data.edit = editData
      next(er)
    })
  }

  var errState = null
  var didStdin = false
  files.forEach(function (f) {
    if (f === '-') {
      if (!didStdin) {
        didStdin = true
        var stdinData = ''
        process.stdin.setEncoding('utf8')
        process.stdin.on('data', function(chunk) {
          stdinData += chunk
        })
        process.stdin.on('error', function(er) {
          next(er)
        })
        process.stdin.on('end', function() {
          data.files['gistfile.' + type] = { content: stdinData }
          next()
        })
      }
    } else {
      fs.readFile(f, 'utf8', function(er, fileData) {
        if (er)
          next(er)
        else {
          data.files[f.replace(/\\|\//g, '-')] = { content: fileData }
          next()
        }
      })
    }
  })

  function next(er) {
    if (errState)
      return
    else if (er)
      return cb(errState = er)
    else if (--c === 0) {
      cb(null, data)
    }
  }
}

function getEditData(cb) {
  debug('getEditData %s', 'https://api.github.com/gists/' + edit)
  var r = url.parse('https://api.github.com/gists/' + edit)
  r.headers = {
    'user-agent': userAgent,
  }
  https.get(r, function(res) {
    debug('getEditData', res.statusCode, res.headers)
    var j = ''
    res.setEncoding('utf8')
    res.on('data', function(c) {
      j += c
    })
    res.on('end', function() {
      debug(j)
      j = JSON.parse(j)

      if (res.statusCode !== 200)
        cb(new Error('Invalid gist ID: ' + edit))
      else
        cb(null, j)
    })
  }).on('error', cb)
}
