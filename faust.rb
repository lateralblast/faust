# Name:         faust (Facter Automatic UNIX Symbolic Template)
# Version:      1.7.1
# Release:      1
# License:      CC-BA (Creative Commons By Attrbution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          http://github.com/richardatlateralblast/faust
# Distribution: Solaris, Red Hat Linux, SuSE Linux, Debian Linux,
#               Ubuntu Linux, Mac OS X
# Vendor:       UNIX
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A template to quickly create custom facts via symlinks

# This template will create a custom fact based on whatever file is symlinked
# to it.
#
# The file naming follows the standard below:
#
# module_type_subtype_parameter
#
# module is whatever you've decided to call this module to destinguish it
# from other facts, eg faust
#
# Custom facts are created automatically by symlinking to this file.
#
# Some examples:
#
# List the enabled services on Linux:
#
# ln -s faust.rb faust_linux_services.rb
#
# To check the value of a parameter in a file, eg TIMESYNC in
# /private/etc/hostprofile on OS X:
#
# ln -s faust.rb faust_darwin_file_private_etc_host_config_parameter_TIMESYNC.rb
#
# Refer to http://github.com/richardatlateralblast/faust

require 'facter'
require 'rexml/document'

# Get file name for processing

full_name = __FILE__
file_name = File.basename(full_name,".*")

# Doing file system searches takes time
# Only enable it if it's needed

$fs_search = "no"

# Global declaration for A-z for different greps

if RUBY_PLATFORM.match(/linux/)
  $atoz = "a-Z"
else
  $atoz = "A-z"
end

# Get the members of a group

def handle_groupmembers(type)
  if File.exist?("/etc/group")
    group = type.gsub(/groupmembers/,"")
    fact  = %x[cat /etc/group |grep '#{group}:' |cut -f4 -d:].gsub("\n","")
  end
  return fact
end

# Get the value of a parameter from a file

def handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
  if file_info[-1] == type
    fact = handle_file_content(kernel,type,file_info,os_distro,os_version)
  else
    file = get_config_file(kernel,modname,type,file_info,os_distro,os_version)
    if file
      if File.exist?(file) or File.symlink?(file)
        if type =~ /hostsallow|hostsdeny|snmp|sendmailcf|ntp/
          param = file_info[2..-1].join(" ")
          if type =~ /hostsallow|hostsdeny/
            fact = %x[cat #{file} |grep -v '#' |grep '#{param}']
            if fact
              fact = fact.gsub(/\n/,",")
            end
          else
            param = file_info[2..-1].join(" ")
            fact  = %x[cat #{file} |grep -v '^#' |grep '#{param}'].gsub("\n","")
          end
        else
          param = file_info[2..-1].join("_")
          case type
          when /rmmount|pam|login|gdminit|auditrules|limits/ # Files where we need the whole line
            fact = %x[cat #{file} |grep -v '^#' |grep '#{param}'].gsub("\n","")
          when /ssh|apache|init|umask|cups/ # File where parameter is separated from value by space
            fact = %x[cat #{file} |grep -v '^#' |grep '#{param} ' |grep -v '#{param}[#{$atoz},0-9]' |awk '{print $2}'].gsub("\n","")
            if type == "sshd" or type == "ssh" # With ssh fetch commented out default if we return no value
              if fact !~ /[A-z]|[0-9]/
                fact = %x[cat #{file} |grep '#{param} ' |grep -v '#{param}[#{$atoz},0-9]' |awk '{print $2}' |head -1].gsub("\n","")
              end
            end
          when /aliases|event|xscreensaver/ # Foe files where parameter is separated from value by a colon
            fact = %x[cat #{file} |grep -v '^#' |grep '#{param}' |grep -v '#{param}[#{$atoz},0-9]' |cut -f2 -d: |sed 's/ //g'].gsub("\n","")
          else # Otherwise assume the separator is an equals
            if file =~ /sudoers/ and kernel == "Darwin"
              fact = %x[sudo sh -c \"cat #{file} |grep -v '^#' |egrep '#{param}=|#{param} =' |grep -v '#{param}[#{$atoz},0-9]' |cut -f2 -d= |sed 's/ //g'\"].gsub("\n","")
            else
              fact = %x[cat #{file} |grep -v '^#' |egrep '#{param}=|#{param} =' |grep -v '#{param}[#{$atoz},0-9]' |cut -f2 -d= |sed 's/ //g'].gsub("\n","")
            end
          end
        end
      else
        fact = "file does not exist"
      end
    else
      fact = "file does not exist"
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
    if fact
      fact = fact.gsub(/\n/,",")
    end
  end
  return fact
end

def handle_sunos_coreadm(type,file_info)
  param = file_info[2..-1].join(" ")
  fact  = %x[coreadm |grep '#{param}' |cut -f2 -d: |sed 's/^ //g'].gsub("\n","")
  return fact
end

def handle_sunos_logadm(type,file_info)
  log  = "/"+file_info[2..-1].join("/")
  fact = %x[logadm -V |grep -v '^#' |grep '#{log}'].gsub("\n","")
  return fact
end

def handle_sunos_ndd(type,file_info,os_version)
  if os_version =~ /^10/
    driver = "/dev/"+file_info[2]
    param  = file_info[2..-2].join("_")
    if param == "tcp_extra_priv_ports_add"
      fact = %x[ndd -get #{driver} tcp_extra_priv_ports #{param}].gsub("\n","")
    else
      fact = %x[ndd -get #{driver} #{param}].gsub("\n","")
    end
  end
  return fact
end

def handle_sunos_ipadm(type,file_info,os_version)
  if os_version =~ /^11/
    driver = file_info[2]
    param  = "_"+file_info[3..-1].join("_")
    fact   = %x[ipadm show-prop -p #{param} #{driver} -co current].gsub("\n","")
  end
  return fact
end

def handle_sunos_inetadm(file_info,os_version)
  if os_version =~ /10|11/
    file_info = file_info[2..-1].join("_")
    if file_info =~ /param/
      (service,param) = file_info.split("_param_")
      if service !~ /^svc/
        service = "svc:/"+service
      else
        service = service.gsub(/_/,"/")
      end
      fact = %x[inetadm -l #{service} |grep '#{param}' |cut -f2 -d=].gsub("\n","")
    end
  end
  return fact
end

def handle_sunos_svc(file_info,os_version)
  if os_version =~ /10|11/
    file_info = file_info[2..-1].join("_")
    if file_info =~ /prop/
      (service,param) = file_info.split(/_prop_/)
      if service !~ /^svc/
        service = "svc:/"+service.gsub(/_/,"/")
      else
        service = service.gsub(/_/,"/")
      end
      param = param.split("_")
      param = param[0]+"/"+param[1..-1].join("_")
      fact  = %x[svcprop -p #{param} #{service}].gsub("\n","")
    end
  end
  return fact
end

def handle_sunos_routeadm(file_info,os_version)
  if os_version =~ /10|11/
    param = file_info[2]
    fact  = %x[routeadm -p #{param} |cut -f4 -d= |sed 's/ //g'].gsub("\n","")
  end
  return fact
end

def handle_sunos_poweradm(file_info)
  param = file_info[2]
  fact  = %x[poweradm list |grep '#{param}' |awk '{print $2}' |cut -f2 -d=].gsub("\n","")
  return fact
end

def handle_sunos_power(kernel,modname,type,file_info,os_version)
  os_distro = ""
  if os_version =~ /^11/
    fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
  else
    fact = handle_sunos_poweradm(file_info)
  end
  return fact
end

def handle_sunos_eeprom(file_info)
  param = file_info[2..-1].join("-")
  fact  = %x[eeprom |grep '#{param}' |cut -f2 -d=].gsub("\n","")
  return fact
end

def handle_sunos_extendedattributes(modname,file_info)
  search = Facter.value("#{modname}_filesystemsearch")
  if search != "no"
    fact = %x[find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -xattr -print]
  end
  return fact
end

def handle_sunos(kernel,modname,type,file_info,fact,os_version)
  os_distro = ""
  case type
  when /cron$|login$|syssuspend$|passwd$|system$|^auditclass$|^auditevent$|^auditcontrol$|^audituser$|defadduser$|inetinit$|rmmount$|telnetd$|keyserv$|inetd$|syslogd$|init$|umask$/
    fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
  when /power/
    fact = handle_sunos_power(kernel,modname,type,file_info,os_version)
  when /xresourcesfiles|xsysresourcesfiles/
    fact = handle_sunos_resourcefiles(type,file_info)
  when "coreadm"
    fact = handle_sunos_coreadm(type,file_info)
  when "logadm"
    fact = handle_sunos_logadm(type,file_info)
  when "ndd"
    fact = handle_sunos_ndd(type,file_info,os_version)
  when "ipadm"
    fact = handle_sunos_ipadm(type,file_info,os_version)
  when "inetadm"
    fact = handle_sunos_inetadm(file_info,os_version)
  when "svc"
    fact = handle_sunos_svc(file_info,os_version)
  when "routeadm"
    fact = handle_sunos_routeadm(file_info,os_version)
  when "eeprom"
    fact = handle_sunos_eeprom(file_info)
  when "extendedattributes"
    fact = handle_sunos_extendedattributes(modname,file_info)
  end
  return fact
end

# FreeBSD specific facts

def handle_freebsd(kernel,modname,type,file_info,fact)
  os_distro  = ""
  os_version = ""
  case type
  when /login$|rc$|sysctl$|rcconf$|rc.conf$|rclocal$|rc.local$/
    fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
  end
  return fact
end

# Get config file

def get_config_file(kernel,modname,type,file_info,os_distro,os_version)
  if file_info.to_s =~ /configfile|initfile/
    if file_info.to_s =~ /configfile/
      file = handle_configfile(kernel,type,file_info,os_distro,os_version)
    end
    if file_info.to_s =~ /initfile/
      file = handle_initfile(kernel,type,file_info,os_distro,os_version)
    end
  else
    file = handle_configfile(kernel,type,file_info,os_distro,os_version)
  end
  if !file
    file = "file does not exist"
  end
  return file
end

# Linux specific facts

def handle_linux_prelink_status(kernel,modname,type,file_info,os_distro,os_version)
  type = type.gsub(/status/,"")
  file = get_config_file(kernel,modname,type,file_info,os_distro,os_version)
  if File.exist?(file)
    fact = %x[cat #{file} |grep PRELINKING |cut -f2 -d= |sed 's/ //g'].gsub("\n","")
  end
  return fact
end

def handle_linux_audit(file_info)
  file = file_info.join("_")
  if file =~ /_etc_|_var_|_run_|_sbin_/
    param = file_info[2..-1].join("/")
  else
    if file =~ /_log_/
      param = file_info[2..-1].join("_")
    else
      param = file_info[2..-1].join(" ")
    end
  end
  if File.exist?(file)
    fact = %x[cat /etc/audit/audit.rules |grep ' #{param} '].gsub("\n","")
  end
  return fact
end

def handle_linux_authconfig(file_info)
  fact = %x[/sbin/authconfig --test |grep '#{param}'].gsub("\n","")
  return fact
end

def handle_linux(kernel,modname,type,file_info,os_distro,fact,os_version)
  case type
  when /avahi$|avahid$|yum$|sysctl$|selinux$|modprobe$|rclocal$|rc.local$|pamsystemauth$|floppycdromfdi$/
    fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
  when "prelinkstatus"
    fact = handle_linux_prelink_status(kernel,modname,type,file_info,os_distro,os_version)
  when "audit"
    fact = handle_linux_audit(file_info)
  end
  return fact
end

# OS X specific facts

def handle_darwin_security(file_info)
  param = file_info[2]
  fact  = %x[/usr/bin/security #{param} 2>&1 |cut -f2 -d=].gsub("\n","")
  return fact
end

def handle_darwin_systemprofiler(file_info)
  pfile = file_info[2]
  param = file_info[3..-1].join(" ")
  fact  = %x[system_profiler #{pfile} |grep '#{param}' |awk -F ': ' '{print $2}'].gsub("\n","")
  return fact
end

def handle_darwin_managednode()
  fact = %x[pwpolicy -n -getglobalpolicy 2>&1].gsub("\n","")
  if fact =~ /Error/
    fact = "/Local/Default"
  end
  return fact
end

def handle_darwin_dscl(subtype,file_info)
  param = file_info[3]
  if subtype != "root"
    subtype = subtype.capitalize
  end
  fact = %x[dscl . -read /Users/#{subtype} #{param} 2>&1 |awk -F: '{print $(NF)}' |sed 's/ //g'].gsub("\n","")
  return fact
end

def handle_darwin_defaults(subtype,file_info)
  param = file_info[3]
  fact  = %x[defaults read /Library/Preferences/#{subtype} #{param} 2>&1 |grep -v default |sed 's/ $//g'].gsub("\n","")
  return fact
end

def handle_darwin_pmset(subtype)
  fact = %x[pmset -g |grep '#{subtype}' |awk '{print $2}' |sed 's/ //g'].gsub("\n","")
  return fact
end

def handle_darwin_pwpolicy(modname,subtype)
  node = Facter.value("#{modname}_darwin_managednode")
  fact = %x[pwpolicy -n #{node} -getglobalpolicy #{subtype} 2>&1 |cut -f2 -d= |sed 's/ //g'].gsub("\n","")
  return fact
end

def handle_darwin_software_update_schedule()
  fact = %x[sudo softwareupdate --schedule |awk '{print $4}'].gsub("\n","")
  return fact
end

def handle_darwin_corestorage(modname,file_info)
  disk  = Facter.value("#{modname}_darwin_bootdisk")
  param = file_info[2..-1].map(&:capitalize).join(" ")
  info  = %x[/usr/sbin/diskutil cs list |egrep '#{param}|Disk' |grep -v "\|"].split("\n")
  count = 0
  info.each do |line|
    line  = line.gsub("\n","")
    if line.match(/#{disk}$/)
      fact = info[count-1].gsub("\n","").split(/#{param}:/)[1].gsub(/ /,"")
      return fact
    end
    count = count+1
  end
  return fact
end

def handle_darwin_spctl(file_info)
  param = file_info[2]
  fact  = %x[/usr/sbin/spctl --#{param}].gsub("\n","")
  return fact
end

def handle_darwin(kernel,modname,type,subtype,file_info,fact)
  os_distro  = ""
  os_version = ""
  case type
  when "systemprofiler"
    fact = handle_darwin_systemprofiler(file_info)
  when "hostconfig"
    fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
  when "newsyslog"
    fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
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
  when "corestorage"
    fact = handle_darwin_corestorage(modname,file_info)
  when "security"
    fact = handle_darwin_security(file_info)
  when "spctl"
    fact = handle_darwin_spctl(file_info)
  end
  return fact
end

# AIX specific facts

def handle_aix_trustchk(file_info)
  param = file_info[2..-1].join("_")
  fact  = %x[/usr/sbin/trustchk -p #{param} 2>&1 |cut -f2 -d=].gsub("\n","")
  return fact
end

def handle_aix_lssec(file_info)
  if file_info =~ /security/
    file   = "/"+file_info[2..4].join("/")
    stanza = file_info[5]
    param  = file_info[6]
  else
    file   = file_info[2]
    if file =~ /login/
      file = "/etc/security/login.cfg"
    end
    if file =~ /user/
      file = "/etc/secuity/user"
    end
    stanza = file_info[3]
    param  = file_info[4]
  end
  fact   = %x[lssec -f #{file} -s #{stanza} -a #{param} 2>&1 |awk '{print $2}' |cut -f2 -d=].gsub("\n","")
  return fact
end

def handle_aix_lsuser(file_info)
  user   = file_info[2]
  param1 = file_info[3]
  param2 = file_info[4]
  if param1 =~ /su/
    fact = %x[lssec -f /etc/security/user -s #{user} -a #{param1} -a #{param2} 2>&1].gsub("\n","")
  else
    fact = %x[lsuser -a #{user} #{param1} #{param2} 2>&1].gsub("\n","")
  end
  return fact
end

def handle_aix(type,file_info,fact)
  case type
  when "trustchk"
    handle_aix_trustchk(file_info)
  when "lssec"
    handle_aix_lssec(file_info)
  when "lsuser"
    handle_aix_lsuser(file_info)
  end
  return fact
end

# Handle syslog type

def handle_syslog(kernel,modname,type,file_info,os_distro,os_version)
  fac  = file_info[2]
  file = get_config_file(kernel,modname,type,file_info,os_distro,os_version)
  if File.exist?(file)
    fact = %x[cat #{file} | grep -v '^#' |grep '#{fac}'].gsub("\n","")
  end
  return fact
end

# Handle pam type

def handle_pam(kernel,type,file_info,os_version)
  service  = file_info[2]
  facility = file_info[3]
  control  = file_info[4]
  modname  = file_info[5..-1].join("_")
  if kernel == "SunOS" and os_version !~ /^11/
    if facility and control and modname
      fact = %x[cat /etc/pam.conf |awk '($1 == "#{service}" && $2 == "#{facility}" && $3 == "#{control}" && $4 == "#{modname}") {print}']
    else
      if facility and control
        fact = %x[cat /etc/pam.conf |awk '($1 == "#{service}" && $2 == "#{facility}" && $3 == "#{control}") {print}']
      else
        if facility
          fact = %x[cat /etc/pam.conf |awk '($1 == "#{service}" && $2 == "#{facility}") {print}']
        else
          fact = %x[cat /etc/pam.conf |awk '($1 == "#{service}") {print}']
        end
      end
    end
  else
    if File.exist?("/etc/pam.d/#{service}")
      if facility and control and modname
        fact = %x[cat /etc/pam.d/#{service}' | awk '($1 == "#{facility}" && $2 == "#{control}" && $3 == "#{modname}") {print}']
      else
        if facility and control
          fact = %x[cat /etc/pam.d/#{service}' |awk '($1 == "#{facility}" && $2 == "#{control}") {print}']
        else
          if facility
            fact = %x[cat /etc/pam.d/#{service}' |awk '($1 == "#{facility}") {print}']
          else
            fact = %x[cat /etc/pam.d/#{service}]
          end
        end
      end
    end
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
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
  if list
    fact = list.select{|element| list.count(element) > 1}
    if fact
      fact = fact.uniq
      fact = fact.join(",")
    end
  end
  return fact
end

# Handle file type

def handle_file(kernel,modname,type,subtype,file_info)
  separator = " "
  comment   = "#"
  file_info = file_info[2..-1].join("_")
  if file_info =~ /param/
    if file_info =~ /parameter/
      (file,param) = file_info.split("_parameter_")
    else
      (file,param) = file_info.split("_param_")
    end
    param = param.gsub(/_star_/,"\*")
    param = param.gsub(/_bang_/,"\!")
    param = param.gsub(/_/," ")
    if file =~ /^system|^apache/
      if file =~ /system/
        file = "/etc/system"
        param   = param.gsub(/\./,':')
      end
      if file =~ /apache/
        file = modname+"_"+kernel.downcase+"_apacheconfigfile"
        file = Facter.value(file)
      end
    else
      file = file.gsub(/^_/,"")
      file = file.gsub(/_/,"/")
      file = file.gsub(/bash\/profile$/,"bash_profile")
      if file =~ /attr$|class$|privs$|warn$/
        info = file.split(/\//)
        file = info[0..-2]+"_"+info[-1]
      end
      file = "/"+file
    end
    if file =~ /hostconfig/
      separator = "="
    end
    if file =~ /hosts\,allow|hosts\,deny/
      separator = ":"
    end
    if File.exist?(file)
      if separator == " "
        if param !~ /^#/
          fact = %x[cat #{file} |grep -v '^#{comment}' |grep '^#{param}' |grep -v '#{param}[#{$atoz},0-9]' |awk '{print $2}' |sed 's/ $//g'].gsub("\n","")
        else
          fact = %x[cat #{file} |grep '^#{param}' |grep -v '#{param}[#{$atoz},0-9]' |awk '{print $2}' |sed 's/ $//g'].gsub("\n","")
        end
      else
        if param !~ /^#/
          fact = %x[cat #{file} |grep -v '^#{comment}' |grep '^#{param}' |grep -v '#{param}[#{$atoz},0-9]' |awk -F#{separator} '{print $2}' |sed 's/ $//g'].gsub("\n","")
        else
          fact = %x[cat #{file} |grep '^#{param}' |grep -v '#{param}[#{$atoz},0-9]' |awk -F#{separator} '{print $2}' |sed 's/ $//g'].gsub("\n","")
        end
      end
    end
  end
  if file_info =~ /line|match/
    if file_info =~ /match/
      (file,line) = file_info.split("_match_")
    else
      (file,line) = file_info.split("_line_")
    end
    line = line.gsub(/_star_/,"\*")
    line = line.gsub(/_bang_/,"\!")
    if file_info !~ /match/ and file !~ /pam/
      line = line.gsub(/_/," ")
    end
    if file =~ /^system|^apache/
      if file =~ /system/
        file = "/etc/system"
        line = line.gsub(/^_/)
      end
      if file =~ /apache/
        file = modname+"_"+kernel+"_qpacheconfigfile"
        file = Facter.value(file)
        line = line.gsub(/^_/,"")
        line = line.gsub(/_/," ")
      end
      if file =~ /allow|deny/
        line = line.gsub(/:_/,": ")
      end
    else
      file = file.gsub(/^_/,"")
      file = file.gsub(/_/,"/")
      file = "/"+file
      file = file.gsub(/bash\/profile$/,"bash_profile")
      if file =~ /attr$|class$|privs$|warn$/
        info = file.split(/\//)
        file = info[0..-2]+"_"+config_info[-1]
      end
    end
    if File.exist?(file)
      if file_info =~ /line/
        if line !~ /^#/
          fact = %x[cat #{file} |grep -v '^#{comment}' |grep '^#{line}' |sed 's/ $//g'].gsub("\n","")
        else
          fact = %x[cat #{file} |grep '^#{line}' |sed 's/ $//g'].gsub("\n","")
        end
      else
        if line !~ /^#/
          fact = %x[cat #{file} |grep -v '^#{comment}' |grep '#{line}' |sed 's/ $//g'].gsub("\n","")
        else
          fact = %x[cat #{file} |grep '#{line}' |sed 's/ $//g'].gsub("\n","")
        end
      end
    end
  end
  return fact
end

# Handle unownedfiles

def handle_unownedfiles(modname,kernel,type,file_info)
  search = Facter.value("#{modname}_filesystemsearch")
  if search != "no"
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
    if fact
      fact = fact.gsub(/\n/,",")
    end
  end
  return fact
end

def handle_skel_configfile(prefix)
  case prefix
  when "profileskel"
    file = "/etc/skel/profile"
  when "bashprofileskel"
    file = "/etc/skel/.bash_profile"
  else
    file = prefix.gsub(/skel/,"")
    file = "/etc/skel/."+file
  end
  return file
end

# handle init file

def handle_initfile(kernel,type,file_info,os_distro,os_version)
  if type == "perms"
    if file_info[2] == "initfile"
      prefix = file_info[3..-1].join("_")
    else
      prefix = file_info[2].gsub(/initfile/,"")
    end
  else
    if type == "initfile"
      prefix = file_info[2..-1].join("_")
    else
      prefix = type.gsub(/initfile/,"")
    end
  end
  test_file = "/etc/init.d/"+prefix
  if File.exist?(test_file)
    file = test_file
  else
    file = "file does not exist"
  end
  return file
end

# Handle configfile type

def handle_configfile(kernel,type,file_info,os_distro,os_version)
  if type == "perms" or type == "content"
    if file_info[2] == "configfile"
      prefix = file_info[3..-1].join("_")
    else
      prefix = file_info[2].gsub(/configfile/,"")
    end
  else
    if type == "configfile"
      prefix = file_info[2..-1].join("_")
    else
      prefix = type.gsub(/configfile/,"")
    end
  end
  if kernel =~ /Darwin|FreeBSD/
    if prefix =~ /syslog/
      prefix = "newsyslog"
    end
  end
  case prefix
  when "apache"
    if kernel == "Darwin"
      file = "/etc/apache2/httpd.conf"
    end
  when "selinux"
    file = "/etc/selinux/config"
  when "fstab"
    if kernel == "SunOS"
      file = "/etc/vfstab"
    else
      file = "/etc/fstab"
    end
  when "init"
    if kernel == "SunOS"
      file = "/etc/default/init"
    else
      file = "/etc/sysconfig/init"
    end
  when "floppycdromfdi"
    if File.directory?("/usr/share/hal/fdi/95userpolicy")
      file = "/usr/share/hal/fdi/95userpolicy/floppycdrom.fdi"
    else
      if File.directory?("/usr/share/hal/fdi/policy/20thirdparty")
        file = "/usr/share/hal/fdi/policy/20thirdparty/floppycdrom.fdi"
      end
    end
  when "umask"
    if kernel == "SunOS"
      if os_version !~ /10|11/
        file = "/etc/init.d/umask"
      end
    end
  when "smb"
    file = "/etc/samba/smb.conf"
  when "samba"
    file = "/etc/samba/smb.conf"
  when "nddnetwork"
    file = "/etc/init.d/nddnetwork"
  when "user"
    file = "/etc/security/user"
  when /avahid|avahi-daemon/
    file = "/etc/avahi/avahi-daemon.conf"
  when "prelink"
    file = "/etc/prelink.conf"
  when "yum"
    file = "/etc/yum.conf"
  when "cupsd"
    file = "/etc/cups/cupsd.conf"
  when "cups"
    file = "/etc/cups/client.conf"
  when /skel/
    file = handle_skel_configfile(prefix)
  when "syslogd"
    file = "/etc/default/syslogd"
  when "auditrules"
    file = "/etc/audit/rules.d/audit.rules"
  when "keyserv"
    file = "/etc/default/keyserv"
  when "inetd"
    file = "/etc/default/inetd"
  when "newsyslog"
    file = "/etc/newsyslog.conf"
  when "hostconfig"
    file = "/private/etc/hostconfig"
  when "ntp"
    file = "/etc/ntp.conf"
  when "telnetd"
    file = "/etc/default/telnetd"
  when "inetinit"
    file = "/etc/default/inetinit"
  when "rclocal"
    file = "/etc/rc.d/local"
  when "defadduser"
    file = "/usr/sadm/defadduser"
  when "sudoers"
    file = "/etc/sudoers"
  when "sudoerswheel"
    file = "/etc/sudoers.d/wheel"
  when "vfstab"
    file = "/etc/vfstab"
  when "limits"
    file = "/etc/security/limits.conf"
  when "sysctl"
    file = "/etc/sysctl.conf"
  when "rc"
    file = "/etc/rc.conf"
  when "pam"
    file = "/etc/pam.conf"
  when "pamgdmautologin"
    file = "/et/pam.d/gdm-autologin"
  when "pamsshd"
    file = "/etc/pam.d/sshd"
  when "pamsystemauth"
    file = "/etc/pam.d/system-auth"
  when "pamcommonauth"
    file = "/etc/pam.d/common-auth"
  when "pamsu"
    file = "/etc/pam.d/su"
  when "rmmount"
    file = "/etc/rmmount.conf"
  when "login"
    if kernel == "SunOS"
      file = "/etc/default/login"
    else
      if kernel == "AIX"
        file = "/etc/security/login.cfg"
      else
        file = "/etc/login.conf"
      end
    end
  when "su"
    file = "/etc/default/su"
  when "ftpd"
    file = "/etc/proftpd.conf"
  when "ftpdaccess"
    if kernel == "SunOS"
      if os_version =~ /11/
        file = "/etc/proftpd.conf"
      else
        file = "/etc/ftpd/ftpaccess"
      end
    end
    if kernel == "Linux"
      file = "/etc/proftpd.conf"
    end
  when "gdminit"
    file = "/etc/gdm/Init/Default"
  when "gdmbanner"
    file = "/etc/X11/gdm.conf"
  when "gdm"
    file = "/etc/X11/gdm.conf"
  when "ftpdbanner"
    if kernel == "SunOS"
      if os_version =~ /11/
        file = "/etc/proftpd.conf"
      else
        file = "/etc/ftpd/banner.msg"
      end
    end
    if kernel == "Linux"
      file = "/etc/proftpd.conf"
    end
  when "ftpdissue"
    if kernel == "SunOS"
      if os_version =~ /11/
        file = "/etc/proftpd.conf"
      else
        file = "/etc/ftpd/banner.msg"
      end
    end
    if kernel == "Linux"
      file = "/etc/proftpd.conf"
    end
  when "proftpd"
    file = "/etc/proftpd.conf"
  when "vsftpd"
    file = "/etc/vsftpd.conf"
  when /^audit|^exec/
    if prefix =~ /rules/
      file = "/etc/audit/audit.rules"
    end
    if prefix =~ /class|event|control|user/
      file = prefix.gsub(/audit/,"")
      file = "/etc/security/audit_"+file
    end
  when /login|su|power|passwd/
    if kernel == "SunOS"
      file = "/etc/default/#{prefix}"
    else
      file = "/etc/#{prefix}.defs"
    end
  when /pam/
    if kernel == "SunOS"
      if os_version =~ /^11/
        file = "/etc/pam.d/"+prefix.gsub(/pam/,"")
      else
        file = "/etc/pam.conf"
      end
    else
      file = "/etc/pam.d/"+prefix.gsub(/pam/,"")
    end
  when "sshd"
    if File.directory?("/etc/ssh")
      file = "/etc/ssh/sshd_config"
    else
      file = "/etc/sshd_config"
    end
  when "ssh"
    if File.directory?("/etc/ssh")
      file = "/etc/ssh/ssh_config"
    else
      file = "/etc/ssh_config"
    end
  when /grub/
    if kernel == "SunOS"
      file = %x[bootadm list-menu |grep configuration |cut -f2 -d:].gsub("\n","")
      file = file.gsub(/\s+/,"")
      file = file+"/grub.cfg"
    else
      file = "/etc/grub.conf"
    end
  when /sysstat/
    file = "/etc/default/sysstat"
  when /xscreensaver|XScreenSaver/
    file = "/usr/openwin/lib/app-defaults/XScreenSaver"
  when /^syslog$/
    file = "/etc/syslog.conf"
  when /cron|syssuspend|passwd/
    file = "/etc/default/#{prefix}"
  when /system/
    file = "/etc/system"
  when /^mail/
    file = "/etc/sysconfig/mail"
  when /network/
    file = "/etc/sysconfig/network"
  when /modprobe/
    file = "/etc/modprobe.conf"
  when /postfix/
    file = "/etc/postfix/main.cf"
  when /policy/
    file = "/etc/security/policy.conf"
  when /hostsallow/
    file = "/etc/hosts.allow"
  when /hostsdeny/
    file = "/etc/hosts.deny"
  when "sendmailcf"
    file = "/etc/mail/sendmail.cf"
  when "sendmail"
    file = "/etc/default/sendmail"
  when /^rc$|rcconf/
    file = "/etc/rc.conf"
  end
  if file !~ /[A-z]/
    if prefix =~ /aliases/
      search_file = prefix
    else
      search_file = prefix+".conf"
    end
    file_list = []
    dir_list = [
      '/etc' '/etc/sfw', '/etc/apache', '/etc/apache2', '/etc/default',
      '/etc/sysconfig', '/usr/local/etc', '/usr/sfw/etc', '/opt/sfw/etc',
      '/etc/cups', '/etc/default', '/etc/security', '/private/etc',
      '/etc/mail','/etc/krb5','etc/snmp','/etc/selinux','/etc/grub'
    ]
    dir_list.each do |dir_name|
      file=dir_name+"/"+search_file
      if File.exist?(file)
        file_list.push(file)
      end
    end
    file = file_list[0]
  end
  if !file
    file = "file does not exist"
  end
  return file
end

# Handle services type

def handle_services(kernel,type,os_distro,os_version)
  if type == "rctcpservices"
    if kernel == "AIX"
      if File.exist?("/etc/rc,tcpip")
        fact = %x[cat /etc/rc.tcpip |grep -v '^#' |awk '{print $2}']
      end
    end
  end
  if type == "systemservices"
    if kernel == "Darwin"
      fact = %x[launchctl list |awk '{print $3}' |grep -v '^Label']
    else
      if kernel == "SunOS"
        if os_version =~ /^11/
          fact = %x[svcs -a |egrep '^online|^legacy' |awk '{print $3}']
        else
          fact = %x[find /etc/rc*.d -type f |grep -v "_[#{$atoz}]"]
        end
      end
    end
    if kernel == "Linux"
      if os_distro =~ /Red|SuSE|Scientific/
        fact =%x[/sbin/chkconfig --list |grep on |awk '{print $1}']
      end
      if os_distro =~ /Ubuntu|Debian/
        fact = %x[initctl list |grep run |awk'{print $1}'']
      end
    end
  end
  if type == "upstartservices"
    if kernel == "Linux"
      if os_distro =~ /Ubuntu|Debian/
        fact = %x[initctl list |grep run |awk'{print $1}'']
      end
    end
  end
  if type == "startupservices"
    if kernel != "Darwin"
      fact = %x[find /etc/rc*.d -type f |grep -v '_[#{$atoz}]']
    end
  end
  if type =~ /inet/
    if type =~ /xinet/
      if kernel == "Linux"
        if File.directory?("/etc/xinetd")
          fact = %x[grep enabled /etc/xinetd.d/* |cut -f1 -d:]
        end
      end
    else
      if File.exist?("/etc/inetd.conf")
        fact = %x[cat /etc/inetd.conf |grep -v '^#' |awk '{print $1}']
      end
    end
  end
  if type == "inittabservices"
    if kernel != "Darwin"
      if kernel == "AIX"
        fact = %x[lsitab -a |grep -v '^#' |cut -f1 -d:]
      else
        if File.exist?("/etc/inittab")
          fact = %x[cat /etc/inittab |grep -v '^#' |cut -f1 -d:]
        end
      end
    end
  end
  if type == "consoleservices"
    if kernel == "SunOS"
      fact = %x[/usr/sbin/consadm -p]
    end
    if kernel == "Linux"
      if File.exist?("/etc/securetty")
        fact = %x[cat /etc/securetty]
      end
    end
  end
  if type == "serialservices"
    if kernel == "AIX"
      fact = %x[lsitab –a |grep 'on:/usr/sbin/getty']
    end
    if kernel == "SunOS"
      if os_version =~ /^11/
        fact = %x[svcs -a |grep online| grep console |grep 'term']
      else
        fact = %x[pmadm -L |egrep 'ttya|ttyb']
      end
    end
    if kernel == "FreeBSD"
      if File.exist?("/etc/ttys")
        fact = %x[cat /etc/ttys |grep dialup |grep -v off |egrep 'ttya|ttyb']
      end
    end
    if kernel == "Linux"
      if File.exist?("/etc/inittab")
        fact = %x[cat /etc/inittab |grep -v '^#' |grep getty |egrep 'ttya|ttyb']
      end
    end
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle exists

def handle_exists(file_info)
  fact = "no"
  fs_item = "/"+file_info[2..-1].join("/")
  if File.exist?(fs_item) or File.directory?(fs_item) or File.symlink?(fs_item)
    fact = "yes"
  end
  return fact
end

# Handle legacy packages type (Solaris 11)

def handle_legacypackages(kernel,os_distro,os_version)
  if kernel == "SunOS"
    fact = %x[pkginfo -l |egrep 'PKGINST:|VERSION:' |awk '{print $2}'].gsub(/\s+VERSION:\s+/,":").gsub(/\s+PKGINST:\s+/,"")
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle installedpackages type

def handle_installedpackages(kernel,os_distro,os_version)
  if kernel == "SunOS"
    if os_version =~ /11/
      fact = %x[pkg info -l |egrep 'Name:|Version:' |awk '{print $1$2}'].gsub(/\nVersion:\s+/,":").gsub(/\nName:\s+/,",")
    else
      fact = %x[pkginfo -l |egrep 'PKGINST:|VERSION:' |awk '{print $1$2}'].gsub(/\nVERSION:\s+/,":").gsub(/\nPKGINST:\s+/,",")
    end
  end
  if kernel == "Linux"
    if os_distro =~ /Ubuntu|Debian/
      fact = %x[dpkg -l |awk '{print $2}']
    else
      fact = %x[rpm -qai |egrep '^Name|^Version' |awk -F ':' '{print $1$2}'].gsub(/\nVersion\s+/,":").gsub(/\nName\s+/,",")
    end
  end
  if kernel == "Darwin"
    fact = %x[pkgutil --pkgs]
  end
  if kernel == "AIX"
    fact = %x[lslpp -L |awk '{print $1}']
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle dotfiles type

def handle_dotfiles(modname)
  search = Facter.value("#{modname}_filesystemsearch")
  if search != "no"
    dot_files = []
    if File.exist?("/etc/passwd")
      home_dirs = %x[cat /etc/passwd |grep -v '^#' |cut -f6 -d: |uniq]
    end
    home_dirs = home_dirs.split(/\n/)
    home_dirs.each do |home_dir|
      if File.directory?(home_dir)
        if home_dir !~ /^\/$/
          file_list = %x[sudo sh -c "find #{home_dir} -name '.*'"]
          file_list = file_list.split(/\n/)
          file_list.each do |dot_file|
            if File.exist?(dot_file)
              dot_files.push(dot_file)
            end
          end
        end
      end
    end
    if fact
      fact = dot_files.join(",")
    end
  end
  return fact
end

# Handle perms type

def handle_perms(kernel,modname,type,file_info,os_distro,os_version)
  if file_info[2] =~ /configfile|initfile/
    if file_info[2] =~ /configfile/
      fs_item = handle_configfile(kernel,type,file_info,os_distro,os_version)
    end
    if file_info[2] =~ /initfile/
      fs_item = handle_initfile(kernel,type,file_info,os_distro,os_version)
    end
  else
    fs_item = file_info[2..-1]
    fs_item = "/"+fs_item.join("/")
  end
  if !fs_item
    fact = "file does not exist"
  else
    if fs_item =~ /\//
      if File.exist?(fs_item)
        mode    = File.stat(fs_item).mode
        mode    = sprintf("%o",mode)[-4..-1]
        uid     = File.stat(fs_item).uid.to_s
        gid     = File.stat(fs_item).gid.to_s
        user    = %x[cat /etc/passwd |awk -F: '{if ($3 == #{uid}) print $1}'].gsub("\n","")
        group   = %x[cat /etc/group |awk -F: '{if ($3 == #{gid}) print $1}'].gsub("\n","")
        fact    = mode+","+user+","+group
      else
        fact = "file does not exist"
      end
    else
      fact = "file does not exist"
    end
  end
  return fact
end

# Handle mtime type

def handle_mtime(file_info)
  fs_item = file_info[2..-1]
  fs_item = "/"+fs_item.join("/")
  if File.exist?(fs_item)
    fact = (Time.now - File.stat(fs_item).mtime).to_i / 86400.0
    if fact
      fact = fact.to_i.to_s
    end
  end
  return fact
end

# Handle by* types

def handle_readwrite(kernel,type,file_info)
  dir_name = file_info[2..-1]
  dir_name = "/"+dir_name.join("/")
  if File.exist?(dir_name) or File.directory?(dir_name)
    if type =~ /byothers/
      if type =~ /readableorwritable/
        if kernel == "SunOS"
          fact = %x[find #{dir_name} -type f -perm -04 -o -perm -40]
        else
          fact = %x[find #{dir_name} -type f -perm +066]
        end
      else
        if kernel == "SunOS"
          fact = %x[find #{dir_name} -type f -perm -02 -o -perm -20]
        else
          fact = %x[find #{dir_name} -type f -perm +022]
        end
      end
    else
      if type =~ /readableorwritable/
        if kernel == "SunOS"
          fact = %x[find #{dir_name} -type f -perm -04]
        else
          fact = %x[find #{dir_name} -type f -perm +006]
        end
      else
        if kernel == "SunOS"
          fact = %x[find #{dir_name} -type f -perm -02]
        else
          fact = %x[find #{dir_name} -type f -perm +002]
        end
      end
    end
  end
  if fact
    fact = fact.split("\n")
    fact = fact.join(",")
  end
  return fact
end

# Handle worldwritable type

def handle_worldwritable(kernel)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -0002 -print"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \( -type d -o -type f \) -perm -o+w -ls"
  end
  if kernel == "FreeBSD"
    find_command = "find / \( -fstype ufs -type file -perm -0002 -a ! -perm -1000 \) -print"
  end
  fact = %x[#{find_command}]
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle directory listing

def handle_directorylisting(type,file_info)
  dir_name = file_info[2..-1]
  dir_name = "/"+dir_name.join("/")
  if File.exist?(dir_name) or File.directory?(dir_name)
    if type =~ /recursive/
      fact = %x[fine #{dir_name} -type f]
    else
      fact = %x[fine #{dir_name} -maxdepth 1 -type f]
    end
    if fact
      fact = fact.split("\n")
      fact = fact.join(",")
    end
  end
  return fact
end

# Handle symlink type

def handle_symlink(file_info)
  file = file_info[2..-1].join("/")
  if File.symlink?(file)
    fact = File.readlink(file)
  end
  return fact
end

# Handle xml types

def handle_xml_types(type,file_info)
  if type == "launchctl"
    file  = "/System/Library/LaunchDaemons/"+file_info[2]+".plist"
    param = file_info[3..-1].join("_")
  else
    if file_info =~ /param/
      if file_info =~ /param/
        (file,param) = file_info.split("_param_")
      else
        (file,param) = file_info.split("_param_")
      end
    end
  end
  if File.exist?(file)
    xml_file = File.new(file)
    xml_doc  = REXML::Document.new xml_file
    if type == "launchctl"
      fact   = []
      if param == "ProgramArguments"
        xml_doc.elements.each("//array/string") do |element|
          fact.push(element.text)
        end
      end
      if fact
        fact = fact.join(",")
      end
    end
  end
  return fact
end

# Handle inactivewheelusers type
#
# Need to add code for OS X
#

def handle_inactivewheelusers(kernel)
  if kernel != "Darwin"
    fact = []
    if File.exist?("/etc/group")
      user_list = %x[cat /etc/group |grep '^wheel:' |cut -f4 -d:].gsub("\n","")
    end
    user_list = user_list.split(/,/)
    user_list.each do |user_name|
      last_login = %x[last -1 #{user_name} |grep '\[a-z\]' |awk '{print $1}']
      if last_login == "wtmp"
        if File.exist?("/etc/shadow")
          lock_user = %x[cat /etc/shadow |grep '^#{user_name}:' |grep -v 'LK' |cut -f1 -d:]
        end
        if lock_user == user_name
          fact.push(user_name)
        end
      end
    end
    if fact
      fact = fact.join(",")
    end
  end
  return fact
end

# Handle unused groups and gids

def handle_unusedsystem_types(kernel,type)
  unused_list = []
  if type == "unusedgids"
    if File.exist?("/etc/passwd") and File.exist?("/etc/group")
      group_list = %x[cat /etc/group |cut -f3 -d:].split("\n")
      gid_list   = %x[cat /etc/passwd |awk -F':' '{print $2":"$3}'].split(/\n|:/)
      gid_list.each do |gid|
        if !group_list.grep(/#{gid}/)
          if !unused_list.grep(/#{gid}/)
            unused_list.push(gid)
          end
        end
      end
    end
  end
  if type == "unusedgroups"
    if File.exist?("/etc/passwd") and File.exist?("/etc/group")
      group_list = %x[cat /etc/group |cut -f3 -d:].split("\n")
      gid_list   = %x[cat /etc/passwd |awk -F':' '{print $2":"$3}'].split(/\n|:/)
      group_list.each do |group|
        if !gid_list.grep(/#{group}/)
          if !unused_list.grep(/#{gid}/)
            unused_list.push(group)
          end
        end
      end
    end
  end
  if unused_list[0]
    fact = unused_list.join(",")
  end
  return fact
end

# Handle invalid system types

def handle_invalidsystem_types(kernel,type)
  invalid_list = []
  if type == "invalidhomeowners"
    if File.exist?("/etc/passwd")
      user_list    = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1":"$2":"$6}']
    end
    user_list    = user_list.split("\n")
    user_list.each do |user_info|
      (user_name,user_uid,user_home) = user_info.split(/:/)
      if user_name.match(/[A-z]/)
        if !File.directory?(user_home)
          if !invalid_list.grep(/#{user_info}/)
            invalid_list.push(user_info)
          end
        else
          dir_uid = File.stat(user_home).uid
          if user_home != "/"
            if dir_uid != user_uid
              if !invalid_list.grep(/#{user_info}/)
                invalid_list.push(user_info)
              end
            end
          end
        end
      end
    end
  end
  if type == "invalidhomedirs"
    if File.exist?("/etc/passwd")
      user_list    = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1":"$6}']
    end
    user_list    = user_list.split("\n")
    user_list.each do |user_info|
      (user_name,user_home) = user_info.split(/:/)
      if user_name.match(/[A-z]/)
        if user_home
          if !File.directory?(user_home)
            if !invalid_list.grep(/#{user_name}/)
              invalid_list.push(user_name)
            end
          end
        else
          if !invalid_list.grep(/#{user_name}/)
            invalid_list.push(user_name)
          end
        end
      end
    end
  end
  if type == "invalidsystemshells"
    if File.exist?("/etc/passwd")
      user_list    = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1":"$7}']
    end
    user_list    = user_list.split("\n")
    if kernel != "Darwin"
      user_list.each do |user_info|
        (user_name,user_shell) = user_info.split(/:/)
        if user_name.match(/[A-z]/)
          if user_shell
            if !File.exist?(user_shell)
              if !invalid_list.grep(/#{user_name}/)
                invalid_list.push(user_name)
              end
            end
          end
        end
      end
    else
      invalid_list = user_list
    end
  end
  if type == "invalidsystemaccounts"
    if File.exist?("/etc/passwd")
      invalid_list = %x[awk -F: '$3 == "0" { print $1 }' /etc/passwd |grep -v root]
      invalid_list = invalid_list.split("\n")
    end
  end
  if type == "invalidshells"
    if File.exist?("/etc/shells")
      shell_list = %x[cat /etc/shells |grep "^/"]
      shell_list = shell_list.split("\n")
      shell_list.each do |shell|
        if !File.exist?(shell)
          if !invalid_list.grep(/#{shell}/)
            invalid_list.push(shell)
          end
        end
      end
    end
  end
  if invalid_list[0]
    fact = invalid_list.join(",")
  end
  return fact
end

# Handle exec tpye

def handle_exec(file_info)
  exec = file_info[2..-1].join(" ")
  exec = exec.gsub(/pipe/,"|")
  fact = %x[#{exec} 2>&1 |sed 's/ $//g'].gsub("\n","")
  return fact
end

# Handle groupexists type

def handle_groupexists(file_info)
  group_name  = file_info[2]
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
  if kernel =~ /Linux|FreeBSD/
    if kernel == "Linux"
      if File.exist?("/etc/inittab")
        fact = %x[cat /etc/inittab |grep -v '^#' |grep 'sulogin']
      end
    end
    if kernel == "FreeBSD"
      if File.exist?("/etc/ttys")
        fact = %x[cat /etc/ttys |grep -v '^#' |grep 'console']
      end
    end
  end
  return fact
end

# Handle nis type

def handle_nis(kernel,type)
  if kernel != "Darwin"
    if type =~ /group/
      if File.exist?("/etc/group")
        fact = %x[cat /etc/group |grep '^+']
      end
    end
    if type =~ /password/
      if File.exist?("/etc/passwd")
        fact = %x[cat /etc/passwd |grep '^+']
      end
    end
    if fact
      if fact.match(/\n/)
        fact = fact.gsub("\n",/,/)
      end
    end
  end
  return fact
end

# Handle cron type

def handle_cron(kernel,type)
  if type =~ /allow|deny/
    file = type.gsub(/cron/,"")
    file = "/etc/cron"+file
    if File.exist?(file)
      fact = %x[cat #{file}]
      if fact
        fact = fact.split("\n").join(",")
      end
    end
  end
  if type =~ /users/
    if kernel == "SunOS"
      user_list = %x[ls -l /var/spool/cron/crontabs |awk '{print $3}' |grep '[a-Z#{$atoz}]' |uniq]
      user_list = user_list.split("\n").join(",")
    end
    if kernel == "Linux"
      user_list = %x[ls -l /etc/cron.*/ |awk '{print $3}' |grep '[#{$atoz}]' |uniq]
    end
    fact = user_list.split("\n").join(",")
  end
  return fact
end

# Handle suidfiles types

def handle_suidfiles(kernel)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \( -perm -04000 -o -perm -02000 \) -typ e f -ls"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -o -perm -2000 -print"
  end
  fact = %x[#{find_command}]
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle stickybitfiles types

def handle_stickybitfiles(kernel)
  if kernel == "SunOS"
    find_command = "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f \( -perm -0002 -o -perm -1000 \) -print"
  end
  if kernel == "AIX"
    find_command = "find / \( -fstype jfs -o -fstype jfs2 \) \( -perm -00002 -o -perm -01000 \) -typ e f -ls"
  end
  if kernel == "Linux"
    find_command = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -o -perm -1000 -print"
  end
  fact = %x[#{find_command}]
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle readable files types

def handle_readablefiles(type,kernel)
  if type != "readabledotfiles"
    file_name = type.gsub(/files/,"")
  end
  if file_name =~ /equiv/
    file_name = "hosts.equiv"
    home_dirs = [ '/etc' ]
  else
    if type != "readabledotfiles"
      file_name = "."+file_name
    end
    if File.exist?("/etc/passwd")
      home_dirs = %x[cat /etc/passwd |cut -f6 -d":" |grep -v "^/$" |grep -v '^#' |sort |uniq]
    end
    home_dirs = home_dirs.split(/\n/)
    if kernel == "Darwin"
      user_dirs = Dir.entries("/Users")
      user_dirs.each do |user_dir|
        if user_dir.match(/^[A-z]/)
          home_dirs.push(user_dir)
        end
      end
    end
  end
  if home_dirs
    home_dirs.each do |home_dir|
      fact = []
      if File.directory?(home_dir)
        if type == "readabledotfiles"
          files_list = %x[sudo sh -c "find #{home_dir} -name .\[a-Z#{$atoz},0-9\]* -maxdepth 1 -type f -perm +066 2>&1"]
          if files_list =~ /[a-z]/
            files_list = files_list.split(/\n/)
            files_list.each do |check_file|
              if File.exist?(check_file)
                fact.push(check_file)
              end
            end
          end
        else
          check_file = home_dir+"/"+file_name
          if File.exist?(check_file)
            fact.push(check_file)
          end
        end
      end
    end
  end
  if fact
    if fact =~ /[A-z]/
      fact = fact.join(",")
    end
  end
  return fact
end

# Handle sudo type

def handle_sudo(kernel,modname,type,file_info,os_distro,os_version)
  file  = get_config_file(kernel,modname,type,file_info,os_distro,os_version)
  param = file_info[2]
  if file
    if File.exist?(file)
      fact = %x[cat #{file} |grep '#{param}'].gsub("\n","")
    end
  end
  return fact
end

# Handle crontab file

def handle_crontabfile(kernel,type,file_info)
  if type =~ /daily|hourly|monthly|weekly/
    if type =~ /^cron/
      search_file = file_info[-1]
    else
      search_file = type.split(/cron/)[0]
    end
    time = type.split(/cron/)[1].split(/file/)[0]
    fact = "/etc/cron."+time+"/"+search_file
  else
    if type == "crontabfile" or type == "crontab"
      search_file = file_info[-1]
    else
      search_file = type.gsub(/crontabfile/,"")
      search_file = type.gsub(/crontab/,"")
    end
    if kernel == "Linux"
      cron_dir = "/var/spool/cron"
    else
      cron_dir = "/var/spool/cron/crontabs/"
    end
    fact = cron_dir+search_file
  end
  return fact
end

# Handle file content

def handle_file_content(kernel,type,file_info,os_distro,os_version)
  file = handle_configfile(kernel,type,file_info,os_distro,os_version)
  if kernel == "Darwin"
    command = "sudo cat '#{file}'"
  else
    command = "cat '#{file}'"
  end
  if File.exist?(file)
    case file
    when /smb|samba/
      comment = ";"
    when /system/
      comment = "*"
    else
      comment = "#"
    end
    fact = %x[#{command} |grep '[#{$atoz}]' |grep -v '^#{comment}']
  else
    fact = "file does not exist"
  end
  return fact
end

# Handle crontab

def handle_crontab(kernel,type,file_info)
  cron_file = handle_crontabfile(kernel,type,file_info)
  if File.exist?(cron_file)
    if kernel == "Darwin"
      fact = %x[sudo cat #{cron_file}]
    else
      fact = %x[cat #{cron_file}]
    end
  end
  return fact
end

# Handle sshkeys

def handle_sshkeys(type,file_info)
  key_files = handle_sshkeyfiles(type)
  key_files = key_files.split(",")
  key_files.each do |key_file|
    if File.exist?(key_file)
      ssh_keys = %x[cat #{key_file}]
      fact     = fact.push(ssh_keys)
    end
  end
  if fact
    fact = fact.join("\n")
  end
  return fact
end

# Handle sshkeyfiles

def handle_sshkeyfiles(type,file_info)
  if type == "sshkeyfiles"
    user_name = file_info[-1]
  else
    user_name = type.gsub(/sshkeyfiles/,"")
  end
  if kernel == "Darwin" and user_name != "root"
    home_dir = "/Users/"+user_name
  else
    home_dir = %x[grep '#{user_name}:' /etc/passed |cut -f6 -d:].gsub("\n","")
  end
  ssh_dir = home_dir+"/.ssh"
  if File.directory?(ssh_dir)
    fact = %x[find #{ssh_dir} -name "authorized_keys*"]
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle primarygroup

def get_primarygid(user)
  if File.exist?("/etc/passwd")
    gid = %x[cat /etc/passwd |grep '^#{user}:' |cut -f4 -d:].gsub("\n","")
  end
  return gid
end

def handle_primarygroup(type,file_info)
  if type == "primarygroup"
    user = file_info[-1]
  else
    user = type.gsub(/primarygroup/,"")
  end
  gid  = get_primarygid(user)
  if File.exist?("/etc/group")
    fact = %x[cat /etc/group |grep ':#{gid}:' |cut -f1 -d:].gsub("\n","")
  end
  return fact
end

# Handle primarygid

def handle_primarygid(type,file_info)
  if type == "primarygid"
    user = file_info[-1]
  else
    user =type.gsub(/primarygid/,"")
  end
  fact = get_primarygid(user)
  return fact
end

# Handle homedir

def handle_homedir(type,file_info)
  if type == "homedir"
    user = file_info[-1]
  else
    user = type.gsub(/homedir/,"")
  end
  if File.exist?("/etc/passwd")
    fact = %x[cat /etc/passwd |grep '^#{user}:' |cut -f6 -d:].gsub("\n","")
  end
  return fact
end

# Handle env

def handle_env(type,file_info)
  if type == "env"
    user = file_info[2]
    if file_info[3]
      param = file_info[3..-1].join("_")
      fact = %x[sudo su - #{user} -c \"set |grep '^#{param}'\"].gsub("\n","")
    else
      fact = %x[sudo su - #{user} -c 'set']
    end
  else
    user  = type.gsub(/env$/,"")
    if file_info[2]
      param = file_info[2..-1].join("_")
      fact = %x[sudo su - #{user} -c \"set |grep '^#{param}'\"].gsub("\n","")
    else
      fact = %x[sudo su - #{user} -c 'set']
    end
  end
  return fact
end

# Handle reserveduids
#
# Need to add code for OS X
#

def handle_reserveduids()
  if File.exist?("/etc/passwd")
    fact = %x[cat /etc/passwd | awk -F: '($3 < 100) { print $1 }']
  end
  if fact
    fact = fact.gsub(/\n/,"")
  end
  return fact
end

# Handle userlist

def handle_userlist()
  if File.exist?("/etc/passwd")
    fact = %x[cat /etc/passwd |grep -v '^#' |cut -f1 -d:]
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle uid list

def handle_uidlist()
  if File.exist?("/etc/passwd")
    fact = %x[cat /etc/passwd |grep -v '^#' |awk -F':' '{print $1":"$3}']
  end
  if fact
    fact = fact.gsub(/\n/,",")
  end
  return fact
end

# Handle emptypasswordfields
#
# Need to add code for OS X
#

def handle_emptypasswordfields(kernel)
  if kernel != "Darwin"
    if File.exist?("/etc/shadow")
      fact = %x[cat /etc/shadow |awk -F":" '{print $1":"$2":"}' |grep '::$' |cut -f1 -d:]
    end
    if fact
      fact = fact.gsub(/\n/,"")
    end
  end
  return fact
end

# Handle issue

def handle_issue()
  file = "/etc/issue"
  if File.exist?(file)
    fact = %x[cat #{file}]
  else
    fact = ""
  end
  return fact
end

# Get bootdisk

def handle_bootdisk(kernel)
  case kernel
  when /Darwin/
    fact = %x[df |grep "/$" |awk '{print $1}'].gsub("\n","")
    fact = File.basename(fact)
  end
  return fact
end

# Get skel information

def handle_skel(file_info)
  fact  = ""
  file  = file_info[2..-2].join("_")
  file  = "/etc/skell/"+file
  param = file_info[-1]
  if File.exist?(file)
    fact = %x[cat #{file} |grep '#{param}'].gsub("\n","")
  end
  return fact
end

# Get exports

def handle_exports(kernel)
  case kernel
  when "SunOS"
    file = "/etc/dfs/dfstab"
  else
    file = "/etc/exports"
  end
  if File.exist?(file)
    fact = %x[cat #{file} |grep -v '^#' |grep '[#{$atoz}]']
  end
  return fact
end

# Get default home directory

def handle_defaulthome(kernel)
  case kernel
  when "SunOS"
    fact = "/export/home"
  when "Darwin"
    fact = "/Users"
  else
    fact = "/home"
  end
  return fact
end

# Get ftpd parameters

def handle_ftpd(kernel,modname,type,file_info,os_distro,os_version)
  param = file_info[-1]
  if kernel == "SunOS" and os_version !~ /11/
    case param.downcase
    when /umask/
      file = "/etc/ftpd/ftpaccess"
    when /banner|issue/
      file ="/etc/ftpd/banner.msg"
    end
  else
    file = "/etc/proftpd.conf"
  end
  if File.exist?(file)
    fact = %x[cat #{file} |grep -i '#{param}' |grep -v '^#' |awk '{print $2}'].gsub("\n","")
  end
  return fact
end

# Get a list of home permissions

def handle_homeperms()
  perm_list = []
  user_list = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1":"$6}']
  user_list = user_list.split("\n")
  user_list.each do |user_info|
    (user_name,user_home) = user_info.split(/:/)
    if user_name.match(/[A-z]/)
      if user_home != "/"
        if File.directory?(user_home)
          mode = File.stat(user_home).mode
          mode = sprintf("%o",mode)[-4..-1]
          info = user_home+":"+mode
          perm_list.push(info)
        end
      end
    end
  end
  if perm_list[0]
    fact = perm_list.join(",")
  end
  return fact
end

# Handle partition

def handle_partition(file_info,kernel)
  if kernel == "SunOS"
    fstab = "/etc/vfstab"
  else
    fstab = "/etc/fstab"
  end
  part = file_info[2..-1].join("/")
  if part == "root"
    part = "/"
  else
    part = "/"+part
  end
  if File.exist?(fstab)
    fact = %x[cat #{fstab} | grep '[[:space:]]#{part}[[:space:]]' |awk '{print $1}']
  else
    fact = "no partition"
  end
  if !fact
    fact = "no partition"
  end
  return fact
end

# Find old users that have not logged in

def handle_oldusers()
  old_users = []
  if File.exist?("/etc/passwd")
    user_list = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1}'].split("\n")
    last_list = %x[last |grep '[#{$atoz}]' |awk '{print $1}'].split("\n")
    user_list.each do |user|
      if !last_list.grep(/#{user}/)
        old_users.push(user)
      end
    end
  end
  if !old_users[0]
    fact = ""
  else
    fact = old_users.join(",")
  end
  return fact
end

# Debug

debug_mode    = "no"
debug_type    = ""
debug_subtype = ""
debug_addtype = ""

if debug_mode == "no"
  get_fact = "yes"
else
  get_fact = "no"
end

if file_name =~ /_chsec_/
  file_name = file_name.gsub(/_chsec_/,"_lssec_")
end

file_info = file_name.split("_")
modname   = file_info[0]
type      = file_info[1]
if file_info[2]
  subtype = file_info[2]
end
if file_info[3]
  addtype = file_info[3]
end

if debug_mode
  if debug_mode == "yes"
    if debug_type
      if debug_type =~ /[A-z]/
        if type != debug_type
          get_fact = "no"
        else
          if debug_subtype
            if debug_subtype =~ /[A-z]/
              if subtype != debug_subtype
                get_fact ="no"
              else
                if debug_addtype
                  if debug_addtype =~ /[A-z]/
                    if addtype != debug_addtype
                      get_fact = "no"
                    else
                      get_fact = "yes"
                    end
                  else
                    get_fact = "yes"
                  end
                else
                  get_fact = "yes"
                end
              end
            else
              get_fact = "yes"
            end
          else
            get_fact = "yes"
          end
        end
      else
        get_fact = "yes"
      end
    else
      get_fact = "yes"
    end
  else
    get_fact = "yes"
  end
else
  get_fact = "yes"
end

# Main code

if file_name !~ /faust|operatingsystemupdate|_info_/ and get_fact == "yes"
  kernel = Facter.value("kernel")
  if kernel == "Linux"
    os_distro = Facter.value("lsbdistid")
  end
  if type =~ /pwpolicy|file|defaults|dscl|pmset/
    subtype   = file_info[2]
  end
  if type
    type = type.gsub(/-/,"")
  end
  if debug_mode == "yes" and file_name.match("_")
    puts "DEBUG: === Debug Information ==="
    puts "DEBUG: FACT:    "+file_name
    puts "DEBUG: KERNEL:  "+kernel
    puts "DEBUG: MODULE:  "+modname
    puts "DEBUG: TYPE:    "+type
    if subtype
      puts "DEBUG: SUBTYPE: "+subtype
    end
    if addtype
      puts "DEBUG: ADDTYPE: "+addtype
    end
  end
  fact_name = file_name.gsub(/\.|:|,|#|-/,"_")
  if type == "launchctl"
    fact_name = fact_name.gsub(/\.plist/,"")
  end
  Facter.add(fact_name) do
    setcode do
      fact = ""
      os_version = Facter.value("kernelrelease")
      if $fs_search == "yes"
        case type
        when "suidfiles"
          fact = handle_suidfiles(kernel)
        when "stickybitfiles"
          fact = handle_stickybitfiles(kernel)
        when "unownedfiles"
          fact = handle_unownedfile(modname,kernel,type,fact_info)
        when "worldwritablefiles"
          fact = handle_worldwritable(kernel)
        end
      end
      case type
      when "content"
        fact = handle_file_content(kernel,type,file_info,os_distro,os_version)
      when "partition"
        fact = handle_partition(file_info,kernel)
      when "oldusers"
        fact - handle_oldusers()
      when "homeperms"
        fact = handle_homeperms()
      when "defaulthome"
        fact = handle_defaulthome(kernel)
      when "exports"
        fact = handle_exports(kernel)
      when "skel"
        fact = handle_skel(file_info)
      when "issue"
        fact = handle_issue()
      when /env$/
        fact = handle_env(type,file_info)
      when /bootdisk/
        fact = handle_bootdisk(kernel)
      when "emptypasswordfields"
        fact = handle_emptypasswordfields(kernel)
      when "userlist"
        fact = handle_userlist()
      when "uidlist"
        fact = handle_uidlist()
      when "reserveduids"
        fact = handle_reserveduids()
      when /primarygroup/
        fact = handle_primarygroup(type,file_info)
      when /primarygid/
        fact = handle_primarygid(type,file_info)
      when /homedir/
        fact = handle_homedir(type,file_info)
      when /sshkeyfiles/
        fact = handle_sshkeyfiles(type,file_info)
      when /sshkeys/
        fact = handle_sshkeys(type,file_info)
      when /rhostsfiles|shostsfiles|hostsequivfiles|netrcfiles|readabledotfiles/
        fact = handle_readablefiles(type,kernel)
      when "symlink"
        fact = handle_symlink(file_info)
      when /cron$/
        fact = handle_cron(kernel,type)
      when /crontab$|crondaily$|cronhourly$|cronweekly$|cronmonthly$/
        fact = handle_crontab(kernel,type,file_info)
      when /^nis/
        fact = handle_nis(kernel,type)
      when /groupmembers/
        fact = handle_groupmembers(type)
      when /xml|plist|launchctl/
        fact = handle_xml_types(type,file_info)
      when /syslog$/
        fact = handle_syslog(kernel,modname,type,file_info,os_distro,os_version)
      when /byothers|byeveryone/
        fact = handle_readwrite(kernel,type,file_info)
      when /directorylisting/
        fact = handle_directorylisting(type,file_info)
      when "inactivewheelusers"
        fact = handle_inactivewheelusers(kernel)
      when "sudo"
        fact = handle_sudo(kernel,modname,type,file_info,os_distro,os_version)
      when "ftpd"
        fact = handle_ftpd(kernel,modname,type,file_info,os_distro,os_version)
      when /ssh$|krb5$|hostsallow$|hostsdeny$|snmp$|sendmail$|ntp$|aliases$|grub$|cups$|apache$|network|xscreensaver|ftpaccess$|proftpd$|vsftpd$|gdmbanner$|gdm$|gdminit$|^rc$|^su$|systemauth$|commonauth$|fstab$|rmmount$|pam$|pamsshd$|pamgdmautologin$|sudoers$|sendmailcf$|skel$|cupsd$|sshd$|sudoerswheel$|auditrules$|smb$|samba$/
        fact = handle_param_value(kernel,modname,type,file_info,os_distro,os_version)
      when "groupexists"
        fact = handle_groupexists(file_info)
      when "sulogin"
        fact = handle_sulogin(kernel)
      when /invalid/
        fact = handle_invalidsystem_types(kernel,type)
      when /unused/
        fact = handle_unusedsystem_types(kernel,type)
      when "exec"
        fact = handle_exec(file_info)
      when "mtime"
        fact = handle_mtime(file_info)
      when "perms"
        fact = handle_perms(kernel,modname,type,file_info,os_distro,os_version)
      when "dotfiles"
        fact = handle_dotfiles(modname)
      when "installedpackages"
        fact = handle_installedpackages(kernel,os_distro,os_version)
      when "legacypackages"
        fact = handle_installedpackages(kernel,os_distro,os_version)
      when "exists"
        fact = handle_exists(file_info)
      when /services/
        fact = handle_services(kernel,type,os_distro,os_version)
      when /duplicate/
        fact = handle_duplicate(type,file_info)
      when /configfile/
        fact = handle_configfile(kernel,type,file_info,os_distro,os_version)
      when /initfile/
        fact = handle_initfile(kernel,type,file_info,os_distro,os_version)
      when /crontabfile|crondailyfile|cronhourlyfile|cronweeklyfile|cronmonthlyfile/
        fact = handle_crontabfile(kernel,type,file_info)
      when "pam"
        fact = handle_pam(kernel,type,file_info,os_version)
      when "file"
        fact = handle_file(kernel,modname,type,subtype,file_info)
      end
      case kernel
      when "Linux"
        fact = handle_linux(kernel,modname,type,file_info,os_distro,fact,os_version)
      when "AIX"
        fact = handle_aix(type,file_info,fact)
      when "SunOS"
        fact = handle_sunos(kernel,modname,type,file_info,fact,os_version)
      when "Darwin"
        fact = handle_darwin(kernel,modname,type,subtype,file_info,fact)
      when "FreeBSD"
        fact = handle_freebsd(kernel,modname,type,file_info,fact)
      end
      if debug_mode == "yes"
        puts "DEBUG: VALUE:   "+fact
      end
      fact
    end
  end
else
  if get_fact == "yes"
    kernel = Facter.value("kernel")
    if debug_mode == "yes" and file_name.match("_")
      puts "DEBUG: === Debug Information ==="
      puts "DEBUG: FACT:    "+file_name
      puts "DEBUG: KERNEL:  "+kernel
      puts "DEBUG: MODULE:  "+modname
      puts "DEBUG: TYPE:    "+type
      if subtype
        puts "DEBUG: SUBTYPE: "+subtype
      end
      if addtype
        puts "DEBUG: ADDTYPE: "+addtype
      end
    end
    if file_name =~ /operatingsystemupdate/
      os_version = Facter.value("kernelrelease")
      kernel     = Facter.value("kernel")
      Facter.add("operatingsystemupdate") do
        setcode do
          if kernel == "SunOS"
            if File.exist?("/etc/release")
              case os_version
              when /^11/
                fact = %x[cat /etc/release |grep Solaris |awk '{print $3}' |cut -f2 -d'.'].gsub("\n","")
              when /^10/
                fact = %x[cat /etc/release |grep Solaris |awk '{print $5}' |cut -f2 -d'_' |sed 's/[a-A]//g'].gsub("\n","")
              else
                fact = %x[cat /etc/release |grep Solaris |awk '{print $4}' |cut -f2 -d'_' |sed 's/[a-Z]//g'].gsub("\n","")
              end
            end
          end
          if kernel == "Darwin"
            fact = Facter.value("macosx_productversion_minor")
          end
          fact
        end
      end
    end
    if file_name =~ /_info_/
      free_mem  = Facter.value("memoryfree_mb")
      if free_mem.to_i > 4000
        base_dir  = File.dirname(full_name)
        base_dir  = base_dir.gsub(/lib\/facter/,"manifests")
        init_file = base_dir+"/"+file_info[2..-1].join("/")+"/init.pp"
        Facter.add(file_name) do
          setcode do
            if File.exist?(init_file)
              fact = %x[cat #{init_file} |grep '^#' |egrep -v 'fact:|::'].gsub("\n","")
            else
              fact = init_file
            end
            fact
          end
        end
      end
    end
  end
end
