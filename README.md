## cryptly-api

**An API service which makes crypto fun, easy, and safe!**


## Status

This project is in development.  Please don't use it for anything serious, yet!


## Purpose

Crypto is hard, CPU intensive, slow, and notoriously easy to mess up.
[cryptly][] is meant to make this whole "crypto" thing simple and accessible for
everyone!

The entire project is open source (visit our [github repo][]) -- everything can
be easily audited for correctness -- want to get involved?  Do it!

My hope is that by being as open and transparent as possible, we can all make
the internet a little bit safer.

-[Randall][]


## API

This section describes the API.  This is not all implemented yet -- and is
mainly serving as a development guide for myself.

### hashers

Hashers are one way functions which take in passwords (or other strings), and
transform these passwords into fixed length strings.

Instead of storing a user's password in your database in plain text, it's always
a better idea to hash your passwords, then store the password hash!

To generate a hash, you pick between several supported hash algorithms.  These
algorithms are maintained for correctness, and will be upgraded as time passes,
ensuring your hashes are progressively upgraded in a backwards compatible way!

**Supported Hashers**

- scrypt
- **bcrypt**
- pbkdf2
- sha512
- sha256
- sha1
- md5

If you're not sure which to use, we recommend you use `scrypt`!  It's incredibly
secure, and essentially impossible to brute force, even by sophisticated
attackers with millions of high powered computers!


#### Usage

Send a `POST` request to `/hashes` with the following JSON body:

``` json
{
  "type": "bcrypt",
  "string": "mypassword",
}
```

The required keys are:

- **type**: The password hashing algorithm to use.
- **string**: The plain text string (most likely a password) to hash (UTF-8
  encoded).

The optional keys are:

- **cost**: The work factor to use when hashing the string.  This means
  different things for different hashing algorithms.  We recommend *not*
  setting this value unless you know what you're doing -- we'll automatically
  provide a high cost factor which is sufficiently strong for each hashing
  algorithm.

After making a request, you'll receive a JSON response like the following:

``` json
{
  "hash": "$2a$10$/R3Mxxcb1k4WaAAx7xwMPeWGINIm2YTdlAH3jEyjHgid21IUGL/ra"
}
```


  [cryptly]: https://cryptly.org "cryptly - Crypto As a Service!"
  [github repo]: https://github.com/rdegges/cryptly-api "cryptly API on Github"
  [Randall]: http://www.rdegges.com "Randall Degges"
