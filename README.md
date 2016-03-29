# ffi-otr

* [Source](https://github.com/sophsec/ffi-otr#readme)
* [Docs](http://www.rubydoc.info/github/sophsec/ffi-otr)
* [Issues](https://github.com/sophsec/ffi-otr/issues)
* [Email](mailto:postmodern.mod3 at gmail.com)

## Description

Ruby FFI bindings for the [Off-The-Record (OTR) Messaging Library][libotr].

## Examples

Minimal example of two users talking to each other:

{include:file:samples/minimal.rb}

A simple jabber echo bot:

{include:file:samples/echo_test.rb}

See {FFI::OTR::UserState} and {FFI::OTR::Callbacks} for details.

## Requirements

* [libotr] >= 3.2.0
* [ffi] ~> 1.0

## Install

    $ gem install ffi-otr

## TODO

* SMP authentication

## License

See {file:LICENSE.txt} for license information.

## Contributors

* Postmodern <postmodern.mod3@gmail.com>
* Marius Hanne <marius.hanne@sourceagency.org>
* Niklas E. Cathor <nilclass@riseup.net>
* Julian Langschaedel <meta.rb@gmail.com>

[libotr]: http://otr.cypherpunks.ca/
[ffi]: http://github.com/ffi/ffi#readme
