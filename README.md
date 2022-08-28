# PHP-SPF-Check-DNS-Direct

Provides a `DNSRecordGetterInterface` to allow you to use custom DNS servers with [mika56/spfcheck](https://github.com/Mika56/PHP-SPF-Check).

It uses [purplepixie/phpdns](https://github.com/purplepixie/phpdns) to get the DNS records.

All the code was initially written by [@btafoya](https://github.com/btafoya) and extracted from the main repository to this one.

## Installation

Ensure you have `mika56/spfcheck` installed, then require `mika56/spfcheck-dns-direct`:

```shell
composer require "mika56/spfcheck-dns-direct:^2.0"
```

## Usage

Instantiate a new `Mika56\SPFCheckDNSDirect\DNSRecordGetterDirect` object and pass it to your `Mika56\SPFCheck\SPFCheck` object:

```php
<?php
use Mika56\SPFCheck\SPFCheck;
use Mika56\SPFCheckDNSDirect\DNSRecordGetterDirect;

require('vendor/autoload.php');

$checker = new SPFCheck(new DNSRecordGetterDirect());
var_dump($checker->getIPStringResult('127.0.0.1', 'test.com'));
```

Note that by default, Google's `8.8.8.8` DNS servers are used. You can change this by passing arguments to the constructor:

```php
public function __construct(
    string $nameserver = '8.8.8.8',
    int $port = 53,
    int $timeout = 30,
    bool $udp = true,
    bool $tcpFallback = true
)
```
