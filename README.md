![alt tag](https://raw.githubusercontent.com/lateralblast/faust/master/faust.jpg)

> Have you not led this life quite long enough?
<br>
> How can a further test delight you?
<br>
> ’Tis very well, that once one tries the stuff,
<br>
> But something new must then requite you.
>
> -- <cite>Mephistopheles<cite>

FAUST
=====

Facter Automatic Unix Symbolic Template

Introduction
------------

Faust is designed to provide an easier and quicker way to create custom
facts for facter. It's creation was driven out of the frustration of having
to create lots of similar facts that simply reused similar code but slightly
different code. It was also driven by the frustration of what appeared to be
lots of different naming schemes for facts.

Even with code control, maintaining lots of similar custom facts with similar
but slightly different code became annoying, especially when developing Puppet
modules. This methodology is no where near perfect but it does make it easier
to manage code and implement common naming schemes for custom facts.

Faust works by creating a symlink to the template with a file name that
follows a set of rules.  By incorporating those rules into the template all
that is needed to create a new fact is create a symlink.

Faust also makes the discovery of rules easier as all you need to do is get
a directory list to see all the custom facts and their names.

Faust can be modified as needed, but the default file naming format is along
the following lines:

MODULENAME_TYPE_SUBTYPE_PARAMETER

This can be expanded as needed, and you can modify it accordingly. You could
choose to remove the module component. I use it so I can easily keep track
of facts produced by the template.

I've chosen the underscore as a type/function separator as it's easier to
handle than spaces in file names. It obviously introduces some issues when
parameters have underscores, so there is some handling in the template to
deal with this.

By doing this the code only needs to be modified in one place. This saves a
lot of time when you are developing Puppet modules which require custom facts
for lots of Operating Systems.

For example, you might have a common custom fact that applies to both Linux
and Solaris. Once the common code is in the template, all you need to do is
create a symlink that has the kernel name in it and the fact is automatically
created.

Similarly, if the custom fact applies to all versions of UNIX, a file name
with 'all' in the KERNEL field will ensure the fact is available to all
Operating Systems. The 'all' will be coverted to the Operating System kernel
name by the template.

For example to create a custom fact that lists all installed packages:

```
ln -s faust.rb MODULE_installedpackages.rb
```

The template has code for determining the installed packages on various
platforms.

License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode

Example Symlinks
----------------

```
$ ls -l
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahi_disable-user-service-publishing.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahi_disallow-other-stacks.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahi_publish-address.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahi_publish-binfo.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahi_publish-domain.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahi_publish-workstation.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 24 Jul 19:05 pulsar_avahiconfigfile.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 30 Jul 22:01 pulsar_commonauth_nullok.rb -> faust.rb
lrwxr-xr-x  1 spindler  staff    8 30 Jul 22:01 pulsar_commonauth_remember.rb -> faust.rb
```

Example Output
--------------

Some example output on Linux:

```
pulsar_configfile_rclocal => /etc/rc.d/local
pulsar_configfile_sendmailcf => /etc/mail/sendmail.cf
pulsar_configfile_sshd => /etc/ssh/sshd_config
pulsar_configfile_sudoers => /etc/sudoers
pulsar_configfile_sysstat => /etc/default/sysstat
pulsar_nisgroupentries =>
pulsar_nispasswordentries =>
pulsar_ntp_options =>
pulsar_ntp_restrict_-6 =>
pulsar_ntp_restrict_default => restrict default nomodify notrap nopeer noquery
pulsar_pamcommonfigfile =>
pulsar_pampasswordauth_authfail =>
pulsar_perms_var_spool_cron => 0700,root,root
pulsar_postfix_inet_interfaces =>
pulsar_primarygid_root => 0
pulsar_rootenv_path => PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin
pulsar_samba_client =>
```

Documentation
-------------

[Examples](https://github.com/lateralblast/faust/wiki/2.-Examples)

[Types](https://github.com/lateralblast/faust/wiki/3.-Types)

[Platforms](https://github.com/lateralblast/faust/wiki/3.1.-Platforms)

- [AIX](https://github.com/lateralblast/faust/wiki/3.1.1.-AIX)
- [OSX](https://github.com/lateralblast/faust/wiki/3.1.2.-OSX)
- [Solaris](https://github.com/lateralblast/faust/wiki/3.1.3.-Solaris)
- [Linux](https://github.com/lateralblast/faust/wiki/3.1.4.-Linux)

[Services](https://github.com/lateralblast/faust/wiki/3.2.-Services)

- [Printing](https://github.com/lateralblast/faust/wiki/3.2.1.-Printing)
- [SNMP and Syslog](https://github.com/lateralblast/faust/wiki/3.2.2.-SNMP-And-Syslog)
- [SSH](https://github.com/lateralblast/faust/wiki/3.2.3.-SSH)
- [DNS](https://github.com/lateralblast/faust/wiki/3.2.4.-DNS)
- [Apache](https://github.com/lateralblast/faust/wiki/3.2.5.-Apache)
- [Mail](https://github.com/lateralblast/faust/wiki/3.2.6.-Mail)
- [FTP](https://github.com/lateralblast/faust/wiki/3.2.7.-FTP)
- [X-Windows](https://github.com/lateralblast/faust/wiki/3.2.8.-X-Windows)

[Operating System Configuration](https://github.com/lateralblast/faust/wiki/3.3.-Operating-System-Configuration)

- [Packages](https://github.com/lateralblast/faust/wiki/3.3.1.-Packages)
- [Password and Privileges](https://github.com/lateralblast/faust/wiki/3.3.2.-Password-And-Privileges)
- [User and Groups](https://github.com/lateralblast/faust/wiki/3.3.3.-User-And-Group)
- [Authentication](https://github.com/lateralblast/faust/wiki/3.3.4.-Authentication)
- [Cron and At](https://github.com/lateralblast/faust/wiki/3.3.5.-Cron-And-At)
- [File and Directory](https://github.com/lateralblast/faust/wiki/3.3.6.-File-And-Directory)
- [Kernel](https://github.com/lateralblast/faust/wiki/3.3.7.-Kernel)

[Challenges](https://github.com/lateralblast/faust/wiki/4.-Challenges)

[Troubleshooting](https://github.com/lateralblast/faust/wiki/5.-Troubleshooting)

Detailed Example
----------------

In case you haven't got the idea, here is an example:

On OS X to determine whether the firewall is enabled, you'd normally type:

```
defaults read /Library/Preferences/com.apple.alf globalstate
```

To create a fact out of this normally, you probably create a fact like this:

```
require 'facter'

kernel    = Facter.value("kernel")
fact_name = "MODULE_#{kernel}_com.apple.alf_globalstate"

Facter.add(fact_name) do
  setcode do
    fact = Facter::Util::Resolution.exec("defaults read /Library/Preferences/com.apple.alf globalstate")
  end
end
```

If you're writing a module that requires you to get the defaults for several
system parameters this gets tedious.

Using the template a custom fact can be created by simply creating a symbolic link:

```
ln -s faust.rb faust_defaults_com.apple.alf_globalstate.rb
```

It will then appear in the facter output:

```
faust_defaults_com.apple.alf_globalstate => 0
```
