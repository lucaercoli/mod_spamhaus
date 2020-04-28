# mod_spamhaus
Domain Name System Blacklists for Apache 2.2. https://lucaercoli.it




What's mod_spamhaus
===================

mod_spamhaus is an Apache module that use DNSBL in order to block spam relay via web forms, preventing URL injection, block http DDoS attacks from bots and generally protecting your web service denying access to a known bad IP address. Default configuration take advantage of the Spamhaus Block List (SBL) and the Exploits Block List (XBL) querying sbl-xbl.spamhaus.org but you can use a different DNSB, for example local rbldnsd instance of sbl-xbl (increasing query performance). Spamhaus's DNSBLs are offered as a free public service for low-volume non-commercial use. To check if you qualify for free use, please see: Spamhaus DNSBL usage criteria (http://www.spamhaus.org/organization/dnsblusage.html)


INSTALLATION
============

Prerequisites

* Apache 2.X - https://apache.org
Other versions may work but have not been tested


Building

If you have got the apxs2 (APache eXtenSion tool) tool installed, write the following commands
to build module:

$ tar zxvf mod_spamhaus-0.X.tar.gz

$ cd mod-spamhaus

$ make

$ make install (as root)



CONFIGURATION
=============

First, you must add following command to the main config file of you're web server to load 
mod_spamhaus module:

LoadModule spamhaus_module   /usr/lib/apache2/modules/mod_spamhaus.so

(The path to mod_spamhaus.so depends on your apache installation)



Directives
==========

MS_Methods

    Syntax:  MS_Methods POST,PUT,OPTIONS
    Default: POST,PUT,OPTIONS
    
    The values admitted are the httpd's methods (GET,POST,etc)
    Module verify remote ip address if the method used by the user is present
    in the value passed to this variable. Methods must be comma-separated

MS_WhiteList

    Syntax:  MS_WhiteList /etc/spamhaus.wl
    Default: no value
   
    Path of whitelist file.
    After you've edit it, you mustn't reload apache. This file will be read only
    when 'data modification time' change. You can add an individual IP address or
    subnets with CIDR. 

MS_DNS

    Syntax:  MS_DNS sbl-xbl.spamhaus.org
    Default: sbl-xbl.spamhaus.org
           
    Name server to use for verify is an ip is blacklisted.
    Using a local rbldnsd instance of sbl-xbl, you can increase query performance


MS_CacheSize

    Syntax:    MS_CacheSize 256
    Default:   512
    Max value: 8192
    
    This directive can manage the number of cache entries.


MS_CustomError

    Syntax:   MS_CustomError "My custom error message"
    Default:  "Access Denied! Your address is blacklisted. More information about this error may be available in the server error log."

    A custom error message that allows you to replace default error message with one you create



Synopsis:
--------

<IfModule mod_spamhaus.c>

MS_METHODS POST,PUT,OPTIONS,CONNECT 

MS_WhiteList /etc/spamhaus.wl

#MS_Dns local.rbldnsd.instance.of.sbl-xbl

MS_CacheSize 256

#MS_CustomError "My custom error"

</IfModule>
