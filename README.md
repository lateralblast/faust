![alt tag](https://raw.githubusercontent.com/richardatlateralblast/faust/master/faust.jpg)

> Have you not led this life quite long enough?
<br>
> How can a further test delight you?
<br>
> ’Tis very well, that once one tries the stuff,
<br>
> But something new must then requite you.
>
> -- <cite>Mephistopheles<cite>

Faust Introduction
==================

faust = Facter Automatic Unix Symbolic Template

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

MODULENAME_KERNEL_TYPE_SUBTYPE_PARAMETER

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
ln -s faust_template.rb MODULE_all_installedpackages.rb
```

The template has code for determining the installed packages on various
platforms.

Example
=======

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
ln -s faust_template.rb faust_darwin_defaults_com.apple.alf_globalstate.rb
```

It will then appear in the facter output:

```
faust_darwin_defaults_com.apple.alf_globalstate => 0
```

# [Examples](2.-Examples) #

# [Types](3.-Types) #

## [Platforms](3.1.-Platforms) ##

- [AIX](3.1.1.-AIX)
- [OSX](3.1.2.-OSX)
- [Solaris](3.1.3.-Solaris)
- [Linux](3.1.4.-Linux)

## [Services](3.2.-Services) ##

- [Printing](3.2.1.-Printing)
- [SNMP and Syslog](3.2.2.-SNMP-And-Syslog)
- [SSH](3.2.3.-SSH)
- [DNS](3.2.4.-DNS)
- [Apache](3.2.5.-Apache)
- [Mail](3.2.6.-Mail)

## [Operating System Configuration](3.3.-Operating-System-Configuration) ##

- [Packages](3.3.1.-Packages)
- [Password and Privileges](3.3.2.-Password-And-Privileges)
- [User and Groups](3.3.3.-User-And-Group)
- [Authentication](3.3.4.-Authentication)
- [Cron and At](3.3.5.-Cron-And-At)
- [File and Directory](3.3.6.-File-And-Directory)

# [Challenges](4.-Challenges) #
