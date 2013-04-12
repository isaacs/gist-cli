# gist-cli

A gist cli client written in Node.

## Usage

Pretty much a direct rip from https://github.com/defunkt/gist/

```
Usage: gist [options] [filename, ...]
Filename '-' forces gist to read from stdin.
gist will read from stdin by default if no files specified
    -p, --[no-]private               Make the gist private
    -t, --type [EXTENSION]           Set syntax highlighting of the Gist by file extension
                                     (Only applies to stdin data, filenames use extension)
    -d, --description DESCRIPTION    Set description of the new gist
    -o, --[no-]open                  Open gist in browser
    -c, --[no-]copy                  Save url to clipboard (osx only)
    -v, --version                    Print version
    -h, --help                       Display this screen
```

## WHY  (I mean, besides the obvious NIH-ism)

I updated git one day, and it blew away my API token that gist was
using.  Since git doesn't actually use a single user-specific API
token any more, it's impossible to get it back, and I couldn't figure
out how to make my gists stop being anonymous, so hence this package.

The first time you use gist, it'll ask you for your github username,
and your password, and then fetch a token and stash it in
`~/.gist-login`

If you don't trust your github password passing through my code
(understandable, I don't fully trust me with my passwords, either),
you can do this yourself quite easily:

```
curl -u YOUR_GITHUB_USERNAME \
  -d '{"scopes":["gist"],"note":"gist access"}' \
  https://api.github.com/authorizations
```

Then curl will ask for your password.

It'll dump some JSON, which contains a token inside of it.

You can put the configs in git like this:

```
git config --global --add gist.username YOUR_GITHUB_USERNAME
git config --global --add gist.token THAT_TOKEN_YOU_GOT
```

Or write this to `~/.gist-auth`

```
[gist]
  username = YOUR_GITHUB_USERNAME
  token = THAT_TOKEN_YOU_GOT
```

Wherever gist finds the configs at, it'll stash them in `~/.gist-auth`
so that it doesn't get confused if you upgrade git or blow away other
files, etc.
