# Name:         faust (Facter Automatic UNIX Symbolic Template)
# Version:      0.4.7
# Release:      1
# License:      Open Source
# Group:        System
# Source:       N/A
# URL:          http://github.com/richardatlateralblast/faust
# Distribution: Solaris, Red Hat Linux, SuSE Linux, Debian Linux,
#               Ubuntu Linux, Mac OS X
# Vendor:       UNIX
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A template to quickly create custom facts via symlinks

# This fact will is based on a template
#
# For example:
#
# module_kernel_type_subtype_parameter
#
# module is whatever you've decided to call this module to destinguish it
# from other facts, eg faust
#
# Some examples:
#
# List the enabled services on Linux:
#
# ln -s faust_template.rb faust_linux_services.rb
#
# To check the value of a parameter in a file, eg TIMESYNC in
# /private/etc/hostprofile on OS X:
#
# ln -s faust_template.rb faust_darwin_file_private_etc_host_config_parameter_TIMESYNC.rb
#
# Refer to http://github.com/richardatlateralblast/faust

require 'facter'
require 'rexml/document'

# Get file name for processing

file_name = __FILE__
file_name = File.basename(file_name,".*")

# Doing file system searches takes time
# Only enable it if it's needed

$fs_search = "no"

# Get the members of a group

def get_group_members(type)
  group = type.gsub(/groupmembers/,"")
  fact  = Facter::Util::Resolution.exec("cat /etc/group |grep '#{group}:' |cut -f4 -d:")
  return fact
end

# Get the value of a parameter from a file

def get_parameter_value(kernel,modname,type,file_info)
  config_file = get_config_file(kernel,modname,type)
  if File.exists?(config_file)
    if type =~ /hostsallow|hostsdeny|snmp|sendmail/
      parameter = file_info[3..-1].join(" ")
      fact      = %x[cat #{config_file} |grep -v '#' |grep '#{parameter}']
      fact      = fact.gsub(/\n/,",")
    else
      parameter = file_info[3..-1].join("_")
      if type =~ /ssh/
        fact = Facter::Util::Resolution.exec("cat #{config_file} |grep -v '^#' |grep '#{parameter}' |awk '{print $2}'")
      else
        fact = Facter::Util::Resolution.exec("cat #{config_file} |grep -v '^#' |grep '#{parameter}' |cut -f2 -d= |sed 's/ //g'")
      end
    end
  end
  return fact
end

# Solaris specific facts

def handle_sunos_resourcefiles(type,file_info)
  dir_name = "/usr/dt/config"
  if File.directory?(dir_name)
    if type == "xresourcesfiles"
      fact = %x[find #{dir_name} -name Xresources]
    end
    if type == "xsysresourcefiles"
      fact = %x[find #{dir_name} -name sys.resources]
    end
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

def handle_sunos_coreadm(type,file_info)
  parameter = file_info[3..-1].join(" ")
  fact      = Facter::Util::Resolution.exec("coreadm |grep '#{parameter}' |cut -f2 -d: |sed 's/^ //g'")
  return fact
end

def handle_sunos_logadm(type,file_info)
  log_name = "/"+file_info[3..-1].join("/")
  fact     = Facter::Util::Resolution.exec("logadm -V |grep -v '^#' |grep '#{log_name}'")
  return fact
end

def handle_sunos_ndd(type,file_info,os_version)
  if os_version =~ /10/
    driver    = "/dev/"+file_info[3]
    parameter = file_info[4..-2].join("_")
    if parameter == "tcp_extra_priv_ports_add"
      fact = Facter::Util::Resolution.exec("ndd -get #{driver} tcp_extra_priv_ports #{parameter}")
    else
      fact = Facter::Util::Resolution.exec("ndd -get #{driver} #{parameter}")
    end
  end
  return fact
end

def handle_sunos_ipadm(type,file_info,os_version)
  if os_version =~ /11/
    driver    = file_info[3]
    parameter = "_"+file_info[4..-2].join("_")
    fact = Facter::Util::Resolution.exec("ipadm show-prop #{driver} -co current #{parameter}")
  end
  return fact
end

def handle_sunos_inetadm(file_info)
  if os_version =~ /10|11/
    file_info = file_info[3..-1].join("_")
    if file_info =~ /parameter/
      (service_name,parameter) = file_info.split("_parameter_")
      service_name = service_name.gsub(/_/,"/")
      fact = Facter::Util::Resolution.exec("inetadm -l #{service_name} |grep #{parameter} |cut -f2 -d=")
    end
  end
  return fact
end

def handle_sunos(kernel,modname,type,file_info,fact,os_version)
  case type
  when /cron|login|sys-suspend|passwd|system|^audit/
    fact = get_parameter_value(kernel,modname,type,file_info)
  when /xresourcesfiles|xsysresourcesfiles/
    fact = handle_sunos_resourcefiles(type,file_info)
  when "coreadm"
    fact = handle_sunos_coreadm(type,file_info)
  when "logadm"
    fact = handle_sunos(type,file_info,fact)
  when "ndd"
    fact = handle_sunos_ndd(type,file_info,os_version)
  when "ipadm"
    fact = handle_sunos_ipadm(type,file_info,os_version)
  when "inetadm"
    fact = handle_sunos_inetadm(file_info,os_version)
  end
  return fact
end

# FreeBSD specific facts

def handle_freebsd(kernel,modname,type,file_info,fact)
  case type
  when /login|rc|sysctl/
    fact = get_parameter_value(kernel,modname,type,file_info)
  end
  return fact
end

# Get conig file

def get_config_file(kernel,modname,type)
  config_file = modname+"_"+kernel.downcase+"_"+type+"configfile"
  config_file = Facter.value(config_file)
  if config_file !~ /[A-z]/
    config_file_list = []
    dir_list = [
      '/etc' '/etc/sfw', '/etc/apache2', '/etc/apache', '/etc/default',
      '/etc/sysconfig', '/usr/local/etc', '/usr/sfw/etc', '/opt/sfw/etc',
      '/etc/cups', '/etc/ssh', '/etc/default', '/etc/security', '/etc/krb5',
      '/etc/snmp'
    ]
    dir_list.each do |dir_name|
      config_file=dir_name+"/"+search_file
      if File.exists?(config_file)
        config_file_list.push(config_file)
      end
    end
    config_file = config_file_list[0]
  end
  return config_file
end

# Linux specific facts

def handle_prelink_status(kernel,modname,type)
  config_file = get_config_file(kernel,modname,type)
  if File.exists?(file_name)
    fact = Facter::Util::Resolution.exec("cat #{config_file} |grep PRELINKING |cut -f2 -d= |sed 's/ //g'")
  end
  return fact
end

def handle_linux_audit(file_info)
  file_name = file_info.join("_")
  if file_name =~ /_etc_|_var_|_run_|_sbin_/
    parameter = file_info[3..-1].join("/")
  else
    if file_name =~ /_log_/
      parameter = file_info[3..-1].join("_")
    else
      parameter = file_info[3..-1].join(" ")
    end
  end
  if File.exists?(file_name)
    fact = Facter::Util::Resolution.exec("cat /etc/audit/audit.rules |grep ' #{parameter} '")
  end
  return fact
end

def handle_linux(kernel,modname,type,file_info,os_distro,fact)
  case type
  when "sysctl"
    fact = handle_sysctl(type,file_info,fact)
  when /avahi|yum/
    fact = get_parameter_value(kernel,modname,type,file_info)
  when "prelinkstatus"
    fact = handle_prelink_status(kernel,modname,type)
  when "audit"
    fact = handle_linux_audit(file_info)
  end
  return fact
end

# OS X specific facts

def handle_darwin_managednode()
  fact = Facter::Util::Resolution.exec("pwpolicy -n -getglobalpolicy 2>&1")
  if fact =~ /Error/
    fact = "/Local/Default"
  end
  return fact
end

def handle_darwin_dscl(subtype,file_info)
  parameter = file_info[4]
  if subtype != "root"
    subtype = subtype.capitalize
  end
  fact = Facter::Util::Resolution.exec("dscl . -read /Users/#{subtype} #{parameter} 2>&1 |awk -F: '{print $(NF)}' |sed 's/ //g'")
  return fact
end

def handle_darwin_defaults(subtype,file_info)
  parameter = file_info[4]
  fact      = Facter::Util::Resolution.exec("defaults read /Library/Preferences/#{subtype} #{parameter} 2>&1 |grep -v default |sed 's/ $//g'")
  return fact
end

def handle_darwin_pmset(subtype)
  fact = Facter::Util::Resolution.exec("pmset -g |grep '#{subtype}' |awk '{print $2}' |sed 's/ //g'")
  return fact
end

def handle_darwin_pwpolicy(modname,subtype)
  managednode = Facter.value("#{modname}_darwin_system_managednode")
  fact        = Facter::Util::Resolution.exec("pwpolicy -n #{managednode} -getglobalpolicy #{subtype} 2>&1 |cut -f2 -d= |sed 's/ //g'")
  return fact
end

def handle_darwin_software_update_schedule()
  fact = Facter::Util::Resolution.exec("sudo softwareupdate --schedule |awk '{print $4}'")
  return fact
end

def handle_darwin(kernel,modname,type,subtype,file_info,fact)
  case type
  when "hostconfig"
    fact = get_parameter_value(kernel,modname,type,file_info)
  when "managednode"
    fact = handle_darwin_managednode()
  when "pmset"
    fact = handle_darwin_pmset(subtype)
  when "dscl"
    fact = handle_darwin_dscl(subtype,file_info)
  when "defaults"
    fact = handle_darwin_defaults(subtype,file_info)
  when "pwpolicy"
    fact = handle_darwin_pwpolicy(modname,subtype)
  when "softwareupdateschedule"
    fact = handle_darwin_software_update_schedule()
  end
  return fact
end

# AIX specific facts

def handle_aix_trustchk(file_info)
  parameter = file_info[3..-1].join("_")
  fact = Facter::Util::Resolution.exec("/usr/sbin/trustchk -p #{parameter} 2>&1 |cut -f2 -d=")
  return fact
end

def handle_aix_lssec(file_info)
  sec_file   = file_info[3]
  sec_stanza = file_info[4]
  parameter  = file_info[5]
  fact = Facter::Util::Resolution.exec("lssec -f #{sec_file} -s #{sec_stanza} -a #{parameter} 2>&1 |awk '{print $2}' |cut -f2 -d=")
  return fact
end

def handle_aix(type,file_info,fact)
  case type
  when "trustchk"
    handle_aix_trustchk(file_info)
  when "lssec"
    handle_aix_lssec(file_info)
  end
  return fact
end

# Handle syslog type

def handle_syslog(kernel,modname,type,file_info)
  facility    = file_info[3]
  config_file = get_config_file(kernel,modname,type)
  fact     = Facter::Util::Resolution.exec("cat #{config_file} | grep -v '^#' |grep '#{facility}'")
  return fact
end

# Handle pam type

def handle_pam(kernel,type,file_info)
  mod_name  = file_info[3]
  parameter = file_info[4..-1].join("_")
  if kernel == "SunOS"
    fact = Facter::Util::Resolution.exec("cat /etc/pam.conf |grep '^#{mod_name}' |grep '#{parameter}'")
  else
    fact = Facter::Util::Resolution.exec("cat /etc/pam..d/#{mod_name}' |grep '#{parameter}'")
  end
end
# Handle duplicate type

def handle_duplicate(type,file_info)
  if type == "duplicateuids"
    list = %x[cat /etc/passwd |cut -f3 -d':']
  end
  if type == "duplicategids"
    list = %x[cat /etc/passwd |cut -f3 -d':']
  end
  if type == "duplicategroups"
    list = %x[cat /etc/passwd |cut -f1 -d':']
  end
  if type == "duplicateusers"
    list = %x[cat /etc/passwd |cut -f1 -d':']
  end
  list = list.split("\n")
  fact = list.select{|element| list.count(element) > 1}
  fact = fact.uniq
  fact = fact.join(",")
  return fact
end

# Handle file type

def handle_file(kernel,modname,type,subtype,file_info)
  separator = " "
  comment   = "#"
  file_info = file_info[3..-1].join("_")
  if file_info =~ /param/
    if file_info =~ /parameter/
      (config_file,parameter) = file_info.split("_parameter_")
    else
      (config_file,parameter) = file_info.split("_param_")
    end
    parameter = parameter.gsub(/_star_/,"\*")
    parameter = parameter.gsub(/_bang_/,"\!")
    parameter = parameter.gsub(/_/," ")
    if config_file =~ /^system|^apache/
      if config_file =~ /system/
        config_file = "/etc/system"
        parameter   = parameter.gsub(/\./,':')
      end
      if config_file =~ /apache/
        config_file = modname+"_"+kernel.downcase+"_apacheconfigfile"
        config_file = Facter.value(config_file)
      end
    else
      config_file = config_file.gsub(/^_/,"")
      config_file = config_file.gsub(/_/,"/")
      config_file = config_file.gsub(/bash\/profile$/,"bash_profile")
      if config_file =~ /attr$|class$|privs$|warn$/
        config_info = config_file.split(/\//)
        config_file = config_info[0..-2]+"_"+config_info[-1]
      end
      config_file = "/"+config_file
    end
    if config_file =~ /hostconfig/
      separator = "="
    end
    if config_file =~ /hosts\,allow|hosts\,deny/
      separator = ":"
    end
    if File.exists?(config_file)
      if separator == " "
        if parameter !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep -v '^#{comment}' |grep '^#{parameter}' |awk '{print $2}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep '^#{parameter}' |awk '{print $2}' |sed 's/ $//g'")
        end
      else
        if parameter !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep -v '^#{comment}' |grep '^#{parameter}' |awk -F#{separator} '{print $2}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep '^#{parameter}' |awk -F#{separator} '{print $2}' |sed 's/ $//g'")
        end
      end
    end
  end
  if file_info =~ /line|match/
    if file_info =~ /match/
      (config_file,line) = file_info.split("_match_")
    else
      (config_file,line) = file_info.split("_line_")
    end
    line = line.gsub(/_star_/,"\*")
    line = line.gsub(/_bang_/,"\!")
    if file_info !~ /match/ and config_file !~ /pam/
      line = line.gsub(/_/," ")
    end
    if config_file =~ /^system|^apache/
      if config_file =~ /system/
        config_file = "/etc/system"
        line        = line.gsub(/^_/)
      end
      if config_file =~ /apache/
        config_file = modname+"_"+kernel+"_qpacheconfigfile"
        config_file = Facter.value(config_file)
        line        = line.gsub(/^_/,"")
        line        = line.gsub(/_/," ")
      end
      if config_file =~ /allow|deny/
        line = line.gsub(/:_/,": ")
      end
    else
      config_file = config_file.gsub(/^_/,"")
      config_file = config_file.gsub(/_/,"/")
      config_file = "/"+config_file
      config_file = config_file.gsub(/bash\/profile$/,"bash_profile")
      if config_file =~ /attr$|class$|privs$|warn$/
        config_info = config_file.split(/\//)
        config_file = config_info[0..-2]+"_"+config_info[-1]
      end
    end
    if File.exists?(config_file)
      if file_info =~ /line/
        if line !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep -v '^#{comment}' |grep '^#{line}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep '^#{line}' |sed 's/ $//g'")
        end
      else
        if line !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep -v '^#{comment}' |grep '#{line}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{config_file} |grep '#{line}' |sed 's/ $//g'")
        end
      end
    end
  end
  return fact
end

# Handle sysctl type

def handle_sysctl(type,file_info)
  parameter = file_info[3..-1].join("_")
  fact      = Facter::Util::Resolution.exec("cat /etc/sysctl.conf |grep '#{parameter}' |awk -F= '{print $2}'")
  return fact
end

# Handle pam type

def handle_ntp(type,file_info)
  parameter = file_info[3..-1].join(" ")
  fact = %x[cat /etc/ntp.conf |grep '#{parameter}']
  return fact
end

# Handle unownedfiles

def handle_unownedfiles(kernel,type,file_info)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs \
    -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
    -o -fstype objfs -o -fstype proc \) -prune \
    -o \( -nouser -o -nogroup \) -print"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} \
    | xargs -I '{}' find '{}' -xdev -nouser -ls"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \
    \( -type d -o -type f \) \( -nouser -o -nogroup \) -ls"
  end
  if kernel == "FreeBSD"
    find_command = "find / \( -nouser -o -nogroup \) -print"
  end
  fact = %x[#{find_command}]
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle apache type

def handle_apache(kernel,modname,type,file_info)
  parameter   = file_info[3]
  config_file = get_config_file(kernel,modname,type)
  if File.exists?(config_file)
    fact = Facter::Util::Resolution.exec("cat #{config_file} |grep '^#{parameter}' |awk '{print $2}' |sed 's/ $//g'")
  end
  return fact
end

# Handle cups type

def handle_cups(kernel,modname,type,file_info)
  parameter   = file_info[3]
  config_file = get_config_file(kernel,modname,type)
  if File.exists?(config_file)
    fact        = Facter::Util::Resolution.exec("cat #{config_file} |grep '^#{parameter}' |awk '{print $2}' |sed 's/ $//g'")
  end
  return fact
end

# Handle configfile type

def handle_configfile(kernel,type,file_info)
  if kernel =~ /Darwin|FreeBSD/
    if type =~ /syslog/
      prefix = "newsyslog"
    end
  end
  case type
  when /apache/
    prefix = "httpd"
  when /cups/
    prefix = "cupsd"
  else
    prefix = type.gsub(/configfile/,"")
  end
  case prefix
  when /^audit|^exec/
    config_file = "/etc/security/"+prefix.gsub(/class/,"_class")
  when /^cron|sys-suspend|paaswd/
    config_file = "/etc/default/#{prefix}"
  when /system/
    config_file = "/etc/system"
  when /policy/
    config_file = "/etc/security/policy.conf"
  when /hostsallow/
    config_file = "/etc/hosts.allow"
  when /hostsdeny/
    config_file = "/etc/hosts.deny"
  when /sendmail/
    config_file = "/etc/mail/sendmail.cf"
  else
    config_file = ""
  end
  if config_file !~ /[A-z]/
    search_file = prefix+".conf"
    config_file_list = []
    dir_list = [
      '/etc' '/etc/sfw', '/etc/apache', '/etc/apache2', '/etc/default',
      '/etc/sysconfig', '/usr/local/etc', '/usr/sfw/etc', '/opt/sfw/etc',
      '/etc/cups', '/etc/default', '/etc/security', '/private/etc',
      '/etc/mail'
    ]
    dir_list.each do |dir_name|
      config_file=dir_name+"/"+search_file
      if File.exists?(config_file)
        config_file_list.push(config_file)
      end
    end
    config_file = config_file_list[0]
  end
  return config_file
end

# Handle services type

def handle_services(kernel,type)
  fact = ""
  if type == "rctcpservices"
    if kernel == "AIX"
      fact = %x[cat /etc/rc.tcpip |grep -v '^#' |awk '{print $2}']
    end
  end
  if type =~ "systemservices"
    if kernel == "Darwin"
      fact = %x[launchctl list |awk '{print $3}' |grep -v '^Label']
    end
    if kernel == "SunOS"
      if os_version == "5.11"
        fact = %x[svcs -a |egrep '^online|^legacy' |awk '{print $3}']
      else
        fact = %x[find /etc/rc*.d -type f |grep -v '_[A-z]']
      end
    end
  end
  if type == "startupservices"
    fact = %x[find /etc/rc*.d -type f |grep -v '_[A-z]']
  end
  if type =~ /inet/
    if type =~ /xinet/
      if kernel == "Linux"
        fact = %x[grep enabled /etc/xinetd.d/* |cut -f1 -d:]
      end
    else
      fact = %x[cat /etc/inetd.conf |grep -v '^#' |awk '{print $1}']
    end
  end
  if type == "inittabservices"
    if kernel == "AIX"
      fact = %x[cat /etc/inittab |grep -v '^#' |cut -f1 -d:]
    else
      fact = %x[lsitab -a |grep -v '^#' |cut -f1 -d:]
    end
  end
  if type == "serialservices"
    if  kernel == "AIX"
      fact = %x[lsitab –a |grep 'on:/usr/sbin/getty']
    end
    if kernel == "SunOS"
      if os_version =~ /11/
        fact = %x[svcs -a |grep online| grep console |grep 'term']
      else
        fact = %x[pmadm -L |egrep 'ttya|ttyb']
      end
    end
    if kernel == "FreeBSD"
      fact = %x[cat /etc/ttys |grep dialup |grep -v off |egrep 'ttya|ttyb']
    end
    if kernel == "Linux"
      fact = %x[cat /etc/inittab |grep -v '^#' |grep getty |egrep 'ttya|ttyb']
    end
  end
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle exists

def handle_exists(file_info)
  fs_item = "/"+file_info[3..-1].join("/")
  if File.exists(fs_item) or File.directory(fs_item)
    fact = "yes"
  else
    fact = "no"
  end
  return fact
end

# Handle installedpackages type

def handle_installedpackages(kernel,os_distro)
  if kernel == "SunOS"
    fact = %x[pkginfo -l |grep PKGINST |awk '{print $2}']
  end
  if kernel == "Linux"
    if os_distro =~ /Ubuntu|Debian/
      fact = %x[dpkg -l |awk '{print $2}']
    else
      fact = %x[rpm -qa]
    end
  end
  if kernel == "Darwin"
    fact = %x[pkgutil --pkgs]
  end
  if kernel == "AIX"
    fact = %x[lslpp -L |awk '{print $1}']
  end
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle dotfiles type

def handle_dotfiles()
  dot_files = []
  home_dirs = %x[cat /etc/passwd |grep -v '^#' |cut -f6 -d: |uniq]
  home_dirs = home_dirs.split(/\n/)
  home_dirs.each do |home_dir|
    if File.directory?(home_dir)
      file_list = %x[/usr/bin/sudo /usr/bin/find #{home_dir} -name '.*']
      file_list = file_list.split(/\n/)
      file_list.each do |dot_file|
        if File.exist?(dot_file)
          dot_files.push(dot_file)
        end
      end
    end
  end
  fact = dot_files.join(",")
  return fact
end

# Handle perms type

def handle_perms(file_info)
  fs_item = file_info[3..-1]
  fs_item = "/"+fs_item.join("/")
  mode    = File.stat(fs_item).mode
  mode    = sprintf("%o",mode)[-4..-1]
  uid     = File.stat(fs_item).uid.to_s
  gid     = File.stat(fs_item).gid.to_s
  user    = %x[cat /etc/passwd |awk -F: '{if ($3 == #{uid}) print $1}'].chomp
  group   = %x[cat /etc/group |awk -F: '{if ($3 == #{gid}) print $1}'].chomp
  fact    = mode+","+user+","+group
  return fact
end

# Handle mtime type

def handle_mtime(file_info)
  fs_item = file_info[3..-1]
  fs_item = "/"+fs_item.join("/")
  fact    = (Time.now - File.stat(fs_item).mtime).to_i / 86400.0
  fact    = fact.to_i.to_s
  return fact
end

# Handle by* types

def handle_readwrite(type,file_info)
  dir_name = file_info[3..-1]
  dir_name = "/"+dir_name.join("/")
  if type =~ /byothers/
    if type =~ /readableorwritable/
      fact     = %x[fine #{dir_name} -type f -perm +066]
    else
      fact     = %x[fine #{dir_name} -type f -perm +022]
    end
  else
    if type =~ /readableorwritable/
      fact     = %x[fine #{dir_name} -type f -perm +006]
    else
      fact     = %x[fine #{dir_name} -type f -perm +002]
    end
  end
  fact     = fact.split("\n")
  fact     = fact.join(",")
  return fact
end

# Handle worldwritable type

def handle_worldwritable(kernel)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs \
      -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
      -o -fstype objfs -o -fstype proc \) -prune \
      -o -type f -perm -0002 -print"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} \
      | xargs -I '{}' find '{}' -xdev -type f -perm -0002"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \
      \( -type d -o -type f \) -perm -o+w -ls"
  end
  if kernel == "FreeBSD"
    find_command = "find / \( -fstype ufs -type file -perm -0002 \
      -a ! -perm -1000 \) -print"
  end
  fact = %x[#{find_command}]
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle directory listing

def handle_directorylisting(type,file_info)
  dir_name = file_info[3..-1]
  dir_name = "/"+dir_name.join("/")
  if type =~ /recursive/
    fact = %x[fine #{dir_name} -type f]
  else
    fact = %x[fine #{dir_name} -maxdepth 1 -type f]
  end
  fact = fact.split("\n")
  fact = fact.join(",")
  return fact
end

# Handle symlink type

def handle_symlink(file_info)
  file_name = file_info[3..-1].join("/")
  fact      = File.readlink(file_name)
  return fact
end

# Handle xml types

def handle_xml_types(type,file_info)
  if type == "launchctl"
    config_file = "/System/Library/LaunchDaemons/"+file_info[3]+".plist"
    parameter   = file_info[4..-1].join("_")
  else
    if file_info =~ /param/
      if file_info =~ /parameter/
        (config_file,parameter) = file_info.split("_parameter_")
      else
        (config_file,parameter) = file_info.split("_param_")
      end
    end
  end
  if File.exists?(config_file)
    xml_file = File.new(config_file)
    xml_doc  = REXML::Document.new xml_file
    if type == "launchctl"
      fact   = []
      if parameter == "ProgramArguments"
        xml_doc.elements.each("//array/string") do |element|
          fact.push(element.text)
        end
      end
      fact = fact.join(",")
    end
  end
  return fact
end

# Handle inactivewheelusers type

def handle_inactivewheelusers()
  fact = []
  user_list = %x[cat /etc/group |grep '^wheel:' |cut -f4 -d:].chomp
  user_list = user_list.split(/,/)
  user_list.each do |user_name|
    last_login = %x[last -1 #{user_name} |grep '\[a-z\]' |awk '{print $1}']
    if last_login == "wtmp"
      lock_user = %x[cat /etc/shadow |grep '^#{user_name}:' |grep -v 'LK' |cut -f1 -d:]
      if lock_user == user_name
        fact.push(user_name)
      end
    end
  end
  fact = fact.join(",")
  return fact
end

# Handle invalid system types

def handle_invalidsystem_types(kernel,type)
  if type == "invalidsystemshells"
    invalid_list = []
    user_list    = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1}']
    user_list    = user_list.split("\n")
    if kernel != "Darwin"
      user_list.each do |user_name|
        invalid_check = %x[cat /etc/shadow |egrep -v "\*|\!\!|NP|UP|LK" |grep '^#{user_name}:'']
        if invalid_check =~ /#{user_name}/
          invalid_list.push(user_name)
        end
      end
    else
      invalid_list = user_list
    end
  end
  if type == "invalidsystemaccounts"
    invalid_list = %x[awk -F: '$3 == "0" { print $1 }' /etc/passwd |grep -v root]
    invalid_list = invalid_list.split("\n")
  end
  if type == "invalidshells"
    if File.exists?("/etc/shells")
      shell_list = %x[cat /etc/shells]
      shell_list = shell_list.split("\n")
      shell_list.each do |shell|
        if !File.exists?(shell)
          invalid_list.push(shell)
        end
      end
    end
  end
  fact = invalid_list.join(",")
  return fact
end

# Handle exec tpye

def handle_exec(file_info)
  exec = file_info[3..-1].join(" ")
  exec = exec.gsub(/pipe/,"|")
  fact = Facter::Util::Resolution.exec("#{exec} 2>&1 |sed 's/ $//g'")
  return fact
end

# Handle groupexists type

def handle_groupexists(file_info)
  group_name  = file_info[3]
  group_check = %x[cat /etc/group |grep '^#{group_name}:']
  if group_check =~ /[A-z]/
    fact = "yes"
  else
    fact = "no"
  end
  return fact
end

# Handle sulogin type

def handle_sulogin(kernel)
  if kernel == "Linux"
    fact = %x[cat /etc/inittab |grep -v '^#' |grep 'sulogin']
  end
  if kernel == "FreeBSD"
    fact = %x[cat /etc/ttys |grep -v '^#' |grep 'console']
  end
  return fact
end

# Handle nis type

def handle_nis(type)
  if type =~ /group/
    fact = %x[cat /etc/group |grep '^+']
  end
  if type =~ /password/
    fact = %x[cat /etc/passwd |grep '^+']
  end
  fact = fact.gsub("\n",/,/)
  return fact
end

# Handle cron type

def handle_cron(kernel,type)
  if type =~ /allow|deny/
    file_name = file_name.gsub(/cron/,"")
    file_name = "/etc/cron"+file_name
    if File.exists?(file_name)
      fact = %x[cat #{file_name}]
      fact = fact.split("\n").join(",")
    end
  end
  if type =~ /users/
    if kernel == "SunOS"
      user_list = %x[ls -l /var/spool/cron/crontabs |awk '{print $3}' |grep '[A-z]' |uniq]
      user_list = user_list.split("\n").join(",")
    end
    if kernel == "Linux"
      user_list = %x[ls -l /etc/cron.*/ |awk '{print $3}' |grep '[A-z]' |uniq]
    end
    fact = user_list.split("\n").join(",")
  end
  return fact
end

# Handle suidfiles types

def handle_suidfiles(kernel)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs \
    -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
    -o -fstype objfs -o -fstype proc \) -prune \
    -o -type f \( -perm -4000 -o -perm -2000 \) -print"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \
    \( -perm -04000 -o -perm -02000 \) -typ e f -ls"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} \
    | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -o -perm -2000 -print"
  end
  fact = %x[#{find_command}]
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle stickybitfiles types

def handle_stickybitfiles(kernel)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs \
    -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
    -o -fstype objfs -o -fstype proc \) -prune \
    -o -type f \( -perm -0002 -o -perm -1000 \) -print"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \
    \( -perm -00002 -o -perm -01000 \) -typ e f -ls"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} \
    | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -o -perm -1000 -print"
  end
  fact = %x[#{find_command}]
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle readable files types

def handle_readablefiles_types(type)
  fact = []
  if type != "readabledotfiles"
    file_name = type.gsub(/files/,"")
    file_name = "."+file_name
  end
  home_dirs = %x[cat /etc/passwd |cut -f6 -d":" |grep -v "^/$" |grep -v '^#' |sort |uniq]
  home_dirs = home_dirs.split(/\n/)
  home_dirs.each do |home_dir|
    if File.directory?(home_dir)
      if type == "readabledotfiles"
        files_list = %x[sudo find #{home_dir} -name .\[A-z,0-9\]* -maxdepth 1 -type f -perm +066]
        if files_list =~ /[a-z]/
          files_list = files_list.split(/\n/)
          files_list.each do |check_file|
            if File.exists?(check_file)
              fact.push(check_file)
            end
          end
        end
      else
        check_file = home_dir+"/"+file_name
        if File.exists?(check_file)
          fact.push(check_file)
        end
      end
    end
  end
  if fact =~ /[A-z]/
    fact = fact.join(",")
  end
  return fact
end

# Handle sudo type

def handle_sudo(kernel,modname,type,file_info)
  config_file = get_config_file(kernel,modname,type)
  parameter   = file_info[3]
  if File.exists?(config_file)
    fact = Facter::Util::Resolution.exec("cat #{config_file} |grep #{parameter}")
  end
  return fact
end

# Main code

if file_name !~ /template|operatingsystemupdate/
  if file_name =~ /_chsec_/
    file_name = file_name.gsub(/_chsec_/,"_lssec")
  end
  kernel = Facter.value("kernel")
  file_info = file_name.split("_")
  modname   = file_info[0]
  f_kernel  = file_info[1]
  type      = file_info[2]
  if f_kernel != "all"
    if f_kernel =~ /osx|darwin/
      f_kernel = "Darwin"
    end
    if f_kernel == "aix"
      f_kernel = "AIX"
    end
    if f_kernel =~ /sunos|solaris/
      f_kernel = "SunOS"
    end
    if f_kernel =~ /linux|Linux|centos|CentOS|Debian|debian|SuSE|suse/
      f_kernel = "Linux"
      os_distro = Facter.value("lsbdistid")
    end
  end
  if type =~ /pwpolicy|file|defaults|dscl|pmset/
    subtype   = file_info[3]
  end
  if f_kernel == "all" or f_kernel == kernel
    if f_kernel == "all"
      file_info[1] = kernel
      fact_name    = file_info.join("_")
    else
      fact_name = file_name
    end
    if type == "launchctl"
      fact_name = fact_name.gsub(/\.plist/,"")
    end
    Facter.add(fact_name) do
      if f_kernel != "all"
        confine :kernel => f_kernel
      end
      setcode do
        fact   = ""
        os_version = Facter.value("operatingsystemrelease")
        if $fs_search == "yes"
          case type
          when "suidfiles"
            fact = handle_suidfiles(kernel)
          when "stickybitfiles"
            fact = handle_stickybitfiles(kernel)
          when "unownedfiles"
            fact = handle_unownedfile(kernel,type,fact_info)
          when "worldwritablefiles"
            fact = handle_worldwritable(kernel)
          end
        end
        case type
        when /rhostfiles|netrcfiles|readabledotfiles/
          fact = handle_readablefiles_types(type)
        when "symlink"
          fact = handle_symlink(file_info)
        when /cron/
          fact = handle_cron(kernel,type)
        when /^nis/
          fact = handle_nis(type)
        when /groupmembers/
          fact = get_group_members(type)
        when /xml|plist|launchctl/
          fact = handle_xml_types(type,file_info)
        when /syslog/
          fact = handle_syslog(kernel,modname,type,file_info)
        when /byothers|byeveryone/
          fact = handle_readwrite(type,file_info)
        when /directorylisting/
          fact = handle_directorylisting(type,file_info)
        when "inactivewheelusers"
          fact = handle_inactivewheelusers()
        when "sudo"
          fact = handle_sudo(kernel,modname,type,file_info)
        when /ssh|krb5|hostsallow|hostsdeny|snmp|sendmail/
          fact = get_parameter_value(kernel,modname,type,file_info)
        when "groupexists"
          fact = handle_groupexists(file_info)
        when "sulogin"
          fact = handle_sulogin(kernel)
        when /invalid/
          fact = handle_invalidsystem_types(kernel,type)
        when "exec"
          fact = handle_exec(file_info)
        when "mtime"
          fact = handle_mtime(file_info)
        when "perms"
          fact = handle_perms(file_info)
        when "dotfiles"
          fact = handle_dotfiles()
        when "installedpackages"
          fact = handle_installedpackages(kernel,os_distro)
        when "exists"
          fact = handle_exists(file_info)
        when /services/
          fact = handle_services(kernel,type)
        when /duplicate/
          fact = handle_duplicate(type,file_info)
        when /configfile/
          fact = handle_configfile(kernel,type,file_info)
        when /apache$/
          fact = handle_apache(kernel,modname,type,file_info)
        when /cups$/
          fact = handle_cups(kernel,modname,type,file_info)
        when "pam"
          fact = handle_pam(kernel,type,file_info)
        when "ntp"
          fact = handle_ntp(type,file_info)
        when "file"
          fact = handle_file(kernel,modname,type,subtype,file_info)
        when "Linux"
          fact = handle_linux(kernel,modname,type,file_info,os_distro,fact)
        end
        case kernel
        when "Linux"
          fact = handle_freebsd(kernel,modname,type,file_info,fact)
        when "AIX"
          fact = handle_aix(type,file_info,fact)
        when "SunOS"
          fact = handle_sunos(kernel,modname,type,file_info,fact,os_version)
        when "Darwin"
          fact = handle_darwin(kernel,modname,type,subtype,file_info,fact)
        when "FreeBSD"
          fact = handle_freebsd(kernel,modname,type,file_info,fact)
        end
        if fact !~ /[0-9]|[A-z]/
          fact = ""
        end
        fact
      end
    end
  end
else
  if file_name =~ /operatingsystemupdate/
    os_version = Facter.value("operatingsystemrelease")
    kernel     = Facter.value("kernel")
    Facter.add("operatingsystemupdate") do
      if $kernel == "SunOS"
        case os_version
        when "5.11"
          fact = Facter::Util::Resolution.exec("cat /etc/release |grep Solaris |awk '{print $3}' |cut -f2 -d'.'`")
        when "5.10"
          fact = Facter::Util::Resolution.exec("cat /etc/release |grep Solaris |awk '{print $5}' |cut -f2 -d'_' |sed 's/[A-z]//g'")
        else
          fact = Facter::Util::Resolution.exec("cat /etc/release |grep Solaris |awk '{print $4}' |cut -f2 -d'_' |sed 's/[A-z]//g'")
        end
      end
      if $kernel == "Darwin"
        fact = Facter.value("macosx_productversion_minor")
      end
      fact
    end
  end
end
