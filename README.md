Introduction
============

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

Challenges
==========

https://github.com/richardatlateralblast/faust/wiki/Challenges

Types
=====

https://github.com/richardatlateralblast/faust/wiki/Types

Examples
========

https://github.com/richardatlateralblast/faust/wiki/Examples
