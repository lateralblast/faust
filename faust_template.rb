# Name:         faust (Facter Automatic UNIX Symbolic Template)
# Version:      0.8.0
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

def handle_groupmembers(type)
  group = type.gsub(/groupmembers/,"")
  fact  = Facter::Util::Resolution.exec("cat /etc/group |grep '#{group}:' |cut -f4 -d:")
  return fact
end

# Get the value of a parameter from a file

def get_param_value(kernel,modname,type,file_info,os_distro,os_version)
  file = get_config_file(kernel,modname,type,os_distro,os_version)
  if File.exists?(file)
    if type =~ /hostsallow|hostsdeny|snmp|sendmailcf|ntp/
      param = file_info[3..-1].join(" ")
      if type =~ /hostsallow|hostsdeny/
        fact = %x[cat #{file} |grep -v '#' |grep '#{param}']
        fact = fact.gsub(/\n/,",")
      else
        param = file_info[3..-1].join(" ")
        fact  = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#' |grep '#{param}'")
      end
    else
      param = file_info[3..-1].join("_")
      case type
      when "pam"
        fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#' |grep '#{param}'")
      when /ssh|apache/
        fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#' |grep '#{param}' |grep -v '#{param}[A-z,0-9]' |awk '{print $2}'")
      when /aliases|event/
        fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#' |grep '#{param}' |grep -v '#{param}[A-z,0-9]' |cut -f2 -d: |sed 's/ //g'")
      else
        fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#' |grep '#{param}' |grep -v '#{param}[A-z,0-9]' |cut -f2 -d= |sed 's/ //g'")
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
  param = file_info[3..-1].join(" ")
  fact  = Facter::Util::Resolution.exec("coreadm |grep '#{param}' |cut -f2 -d: |sed 's/^ //g'")
  return fact
end

def handle_sunos_logadm(type,file_info)
  log  = "/"+file_info[3..-1].join("/")
  fact = Facter::Util::Resolution.exec("logadm -V |grep -v '^#' |grep '#{log}'")
  return fact
end

def handle_sunos_ndd(type,file_info,os_version)
  if os_version =~ /10/
    driver = "/dev/"+file_info[3]
    param  = file_info[4..-2].join("_")
    if param == "tcp_extra_priv_ports_add"
      fact = Facter::Util::Resolution.exec("ndd -get #{driver} tcp_extra_priv_ports #{param}")
    else
      fact = Facter::Util::Resolution.exec("ndd -get #{driver} #{param}")
    end
  end
  return fact
end

def handle_sunos_ipadm(type,file_info,os_version)
  if os_version =~ /11/
    driver = file_info[3]
    param  = "_"+file_info[4..-2].join("_")
    fact   = Facter::Util::Resolution.exec("ipadm show-prop #{driver} -co current #{param}")
  end
  return fact
end

def handle_sunos_inetadm(file_info)
  if os_version =~ /10|11/
    file_info = file_info[3..-1].join("_")
    if file_info =~ /param/
      (service,param) = file_info.split("_param_")
      if service !~ /^svc/
        service = "svc:/"+service
      else
        service = service.gsub(/_/,"/")
      end
      fact = Facter::Util::Resolution.exec("inetadm -l #{service} |grep #{param} |cut -f2 -d=")
    end
  end
  return fact
end

def handle_sunos_svc(file_info,os_version)
  if os_version =~ /10|11/
    file_info = file_info[3..-1].join("_")
    if file_info =~ /prop/
      (service,param) = file_info.split(/_prop_/)
      if service !~ /^svc/
        service = "svc:/"+service.gsub(/_/,"/")
      else
        service = service.gsub(/_/,"/")
      end
      param = param.split("_")
      param = param[0]+"/"+param[1..-1].join("_")
      fact  = Facter::Util::Resolution.exec("svcprop -p #{param} #{service}")
    end
  end
  return fact
end

def handle_sunos_routeadm(file_info,os_version)
  if os_version =~ /10|11/
    param = file_info[3]
    fact  = Facter::Util::Resolution.exec("routeadm -p #{param} |cut -f6 -d= |sed 's/ //g'")
  end
  return fact
end

def handle_sunos_poweradm(file_info)
  param = file_info[3]
  fact  = Facter::Util::Resolution.exec("poweradm list |grep '#{param}' |awk '{print $2}' |cut -f2 -d=")
  return fact
end

def handle_sunos_power(kernel,modname,type,file_info,os_version)
  os_distro = ""
  if os_version == "5.11"
    fact = get_param_value(kernel,modname,type,file_info,os_distro,os_version)
  else
    fact = handle_sunos_poweradm(file_info)
  end
  return fact
end

def handle_sunos_eeprom(file_info)
  param = file_info[3..-1].join("-")
  fact  = Facter::Util::Resolution.exec("eeprom |grep '#{param}' |cut -f2 -d=")
  return fact
end

def handle_sunos_extendedattributes()
  fact = %x[find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -xattr -print]
  return fact
end

def handle_sunos(kernel,modname,type,file_info,fact,os_version)
  os_distro = ""
  case type
  when /cron$|login|sys-suspend|passwd|system|^audit/
    fact = get_param_value(kernel,modname,type,file_info,os_distro,os_version)
  when /power/
    fact = handle_sunos_power(kernel,modname,type,file_info,os_version)
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
  when "svc"
    fact = handle_sunos_svc(file_info,os_version)
  when "routeadm"
    fact = handle_sunos_routeadm(file_info,os_version)
  when "eeprom"
    fact = handle_sunos_eeprom(file_info)
  when "extendedattributes"
    fact = handle_sunos_extendedattributes(file_info)
  end
  return fact
end

# FreeBSD specific facts

def handle_freebsd(kernel,modname,type,file_info,fact)
  os_distro  = ""
  os_version = ""
  case type
  when /login|rc|sysct|rcconf|rc.confl/
    fact = get_param_value(kernel,modname,type,file_info,os_distro,os_version)
  end
  return fact
end

# Get conig file

def get_config_file(kernel,modname,type,os_distro,os_version)
  file_name = type+"configfile"
  file      = modname+"_"+kernel.downcase+"_"+file_name
  file      = Facter.value(file)
  if file !~ /[A-z]/
    file = handle_configfile(kernel,type,file_info,os_distro,os_version)
  end
  return file
end

# Linux specific facts

def handle_prelink_status(kernel,modname,type,os_distro,os_version)
  file = get_config_file(kernel,modname,type,os_distro,os_version)
  if File.exists?(file_name)
    fact = Facter::Util::Resolution.exec("cat #{file} |grep PRELINKING |cut -f2 -d= |sed 's/ //g'")
  end
  return fact
end

def handle_linux_audit(file_info)
  file_name = file_info.join("_")
  if file_name =~ /_etc_|_var_|_run_|_sbin_/
    param = file_info[3..-1].join("/")
  else
    if file_name =~ /_log_/
      param = file_info[3..-1].join("_")
    else
      param = file_info[3..-1].join(" ")
    end
  end
  if File.exists?(file_name)
    fact = Facter::Util::Resolution.exec("cat /etc/audit/audit.rules |grep ' #{param} '")
  end
  return fact
end

def handle_linux_authconfig(file_info)
  fact = Facter::Util::Resolution.exec("/sbin/authconfig --test |grep '#{param}'")
  return fact
end

def handle_linux(kernel,modname,type,file_info,os_distro,fact,os_version)
  case type
  when /avahi|yum|sysctl/
    fact = get_param_value(kernel,modname,type,file_info,os_distro,os_version)
  when "prelinkstatus"
    fact = handle_prelink_status(kernel,modname,typ,os_distro,os_versione)
  when "audit"
    fact = handle_linux_audit(file_info)
  end
  return fact
end

# OS X specific facts

def handle_darwin_security(file_info)
  param = file_info[3]
  fact  = Facter::Util::Resolution.exec("/usr/bin/security #{param} |cut -f2 -d=")
  return fact
end

def handle_darwin_systemprofiler(file_info)
  pfile = file_info[3]
  param = file_info[4..-1].gsub(/_/," ")
  fact  = Facter::Util::Resolution.exec("system_profiler #{pfile} |grep '#{param}' |awk -F ': ' '{print $2}'")
  return fact
end

def handle_darwin_managednode()
  fact = Facter::Util::Resolution.exec("pwpolicy -n -getglobalpolicy 2>&1")
  if fact =~ /Error/
    fact = "/Local/Default"
  end
  return fact
end

def handle_darwin_dscl(subtype,file_info)
  param = file_info[4]
  if subtype != "root"
    subtype = subtype.capitalize
  end
  fact = Facter::Util::Resolution.exec("dscl . -read /Users/#{subtype} #{param} 2>&1 |awk -F: '{print $(NF)}' |sed 's/ //g'")
  return fact
end

def handle_darwin_defaults(subtype,file_info)
  param = file_info[4]
  fact  = Facter::Util::Resolution.exec("defaults read /Library/Preferences/#{subtype} #{param} 2>&1 |grep -v default |sed 's/ $//g'")
  return fact
end

def handle_darwin_pmset(subtype)
  fact = Facter::Util::Resolution.exec("pmset -g |grep '#{subtype}' |awk '{print $2}' |sed 's/ //g'")
  return fact
end

def handle_darwin_pwpolicy(modname,subtype)
  node = Facter.value("#{modname}_darwin_system_managednode")
  fact = Facter::Util::Resolution.exec("pwpolicy -n #{node} -getglobalpolicy #{subtype} 2>&1 |cut -f2 -d= |sed 's/ //g'")
  return fact
end

def handle_darwin_software_update_schedule()
  fact = Facter::Util::Resolution.exec("sudo softwareupdate --schedule |awk '{print $4}'")
  return fact
end

def handle_darwin_corestorage(modname,file_info)
  disk  = Facter.value("#{modname}_darwin_bootdisk")
  param = file_info[3..-1].map(&:capitalize).join(" ")
  info  = %x[/usr/sbin/diskutil cs list |egrep "#{param}|Disk" |grep -v "\|"].split("\n")
  count = 0
  info.each do |line|
    line  = line.chomp
    if line.match(/#{disk}$/)
      fact = info[count-1].chomp.split(/#{param}:/)[1].gsub(/ /,"")
      return fact
    end
    count = count+1
  end
  return fact
end

def handle_darwin_spctl(file_info)
  param = file_info[3]
  fact  = Facter::Util::Resolution.exec("/usr/bin/spctl --#{param}")
  return fact
end

def handle_darwin(kernel,modname,type,subtype,file_info,fact)
  os_distro  = ""
  os_version = ""
  case type
  when "systemprofiler"
    fact = handle_darwin_systemprofiler(file_info)
  when "hostconfig"
    fact = get_param_value(kernel,modname,type,file_info,os_distro,os_version)
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
  param = file_info[3..-1].join("_")
  fact  = Facter::Util::Resolution.exec("/usr/sbin/trustchk -p #{param} 2>&1 |cut -f2 -d=")
  return fact
end

def handle_aix_lssec(file_info)
  if file_info =~ /security/
    file   = "/"+file_info[3..5].join("/")
    stanza = file_info[6]
    param  = file_info[7]
  else
    file   = file_info[3]
    if file =~ /login/
      file = "/etc/security/login.cfg"
    end
    if file =~ /user/
      file = "/etc/secuity/user"
    end
    stanza = file_info[4]
    param  = file_info[5]
  end
  fact   = Facter::Util::Resolution.exec("lssec -f #{file} -s #{stanza} -a #{param} 2>&1 |awk '{print $2}' |cut -f2 -d=")
  return fact
end

def handle_aix_lsuser(file_info)
  user   = file_info[3]
  param1 = file_info[4]
  param2 = file_info[5]
  if param1 =~ /su/
    fact = Facter::Util::Resolution.exec("lssec -f /etc/security/user -s #{user} -a #{param1} -a #{param2} 2>&1")
  else
    fact = Facter::Util::Resolution.exec("lsuser -a #{user} #{param1} #{param2} 2>&1")
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
  fac  = file_info[3]
  file = get_config_file(kernel,modname,type,os_distro,os_version)
  fact = Facter::Util::Resolution.exec("cat #{file} | grep -v '^#' |grep '#{fac}'")
  return fact
end

# Handle pam type

def handle_pam(kernel,type,file_info,os_version)
  service  = file_info[3]
  facility = file_info[4]
  control  = file_info[5]
  modname  = file_info[6..-1].joing("_")
  if kernel == "SunOS" and os_version !~ /11/
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
  fact = fact.gsub(/\n/,",")
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
    if File.exists?(file)
      if separator == " "
        if param !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#{comment}' |grep '^#{param}' |grep -v '#{param}[A-z,0-9]' |awk '{print $2}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{file} |grep '^#{param}' |grep -v '#{param}[A-z,0-9]' |awk '{print $2}' |sed 's/ $//g'")
        end
      else
        if param !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#{comment}' |grep '^#{param}' |grep -v '#{param}[A-z,0-9]' |awk -F#{separator} '{print $2}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{file} |grep '^#{param}' |grep -v '#{param}[A-z,0-9]' |awk -F#{separator} '{print $2}' |sed 's/ $//g'")
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
    if File.exists?(file)
      if file_info =~ /line/
        if line !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#{comment}' |grep '^#{line}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{file} |grep '^#{line}' |sed 's/ $//g'")
        end
      else
        if line !~ /^#/
          fact = Facter::Util::Resolution.exec("cat #{file} |grep -v '^#{comment}' |grep '#{line}' |sed 's/ $//g'")
        else
          fact = Facter::Util::Resolution.exec("cat #{file} |grep '#{line}' |sed 's/ $//g'")
        end
      end
    end
  end
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

# Handle configfile type

def handle_configfile(kernel,type,file_info,os_distro,os_version)
  if type !~ /configfile/
    type = file_info
  end
  if kernel =~ /Darwin|FreeBSD/
    if type =~ /syslog/
      prefix = "newsyslog"
    end
  end
  case type
  when /selinux/
    prefix = "config"
  when /apache/
    prefix = "httpd"
  when /cups/
    prefix = "cupsd"
  else
    prefix = type.gsub(/configfile/,"")
  end
  case prefix
  when /^audit|^exec/
    if prefix =~ /class/
      file = "/etc/security/"+prefix.gsub(/class/,"_class")
    end
    if prefix =~ /event/
      file = "/etc/security/"+prefix.gsub(/event/,"_event")
    end
  when /login|su|power/
    if kernel == "SunOS"
      file = "/etc/default/#{prefix}"
    else
      file = "/etc/#{pefix}.defs"
    end
  when /pam/
    if kernel == "SunOS"
      if os_version =~ /11/
        file = "/etc/pam.d"+prefix.gsub(/pam/,"")
      else
        file = "/etc/pam.conf"
      end
    else
      file = "/etc/pam.d"+prefix.gsub(/pam/,"")
    end
  when /cron|sys-suspend|passwd/
    file = "/etc/default/#{prefix}"
  when /system/
    file = "/etc/system"
  when /^mail/
    file = "/etc/sysconfig/mail"
  when /postfix/
    file = "/etc/postfix/main.cf"
  when /policy/
    file = "/etc/security/policy.conf"
  when /hostsallow/
    file = "/etc/hosts.allow"
  when /hostsdeny/
    file = "/etc/hosts.deny"
  when /sendmailcf/
    file = "/etc/mail/sendmail.cf"
  when /^rc$|rcconf|rc.conf/
    file = "/etc/rc.conf"
  else
    file = ""
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
      if File.exists?(file)
        file_list.push(file)
      end
    end
    file = file_list[0]
  end
  return file
end

# Handle services type

def handle_services(kernel,type,os_distro)
  if type == "rctcpservices"
    if kernel == "AIX"
      fact = %x[cat /etc/rc.tcpip |grep -v '^#' |awk '{print $2}']
    end
  end
  if type == "systemservices"
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
  if type == "consoleservices"
    if kernel == "SunOS"
      fact = %x[/usr/sbin/consadm -p]
    end
    if kernel == "Linux"
      fact = %x[cat /etc/securetty]
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
      fact = %x[fine #{dir_name} -type f -perm +066]
    else
      fact = %x[fine #{dir_name} -type f -perm +022]
    end
  else
    if type =~ /readableorwritable/
      fact = %x[fine #{dir_name} -type f -perm +006]
    else
      fact = %x[fine #{dir_name} -type f -perm +002]
    end
  end
  fact = fact.split("\n")
  fact = fact.join(",")
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
  file = file_info[3..-1].join("/")
  fact = File.readlink(file)
  return fact
end

# Handle xml types

def handle_xml_types(type,file_info)
  if type == "launchctl"
    file  = "/System/Library/LaunchDaemons/"+file_info[3]+".plist"
    param = file_info[4..-1].join("_")
  else
    if file_info =~ /param/
      if file_info =~ /param/
        (file,param) = file_info.split("_param_")
      else
        (file,param) = file_info.split("_param_")
      end
    end
  end
  if File.exists?(file)
    xml_file = File.new(file)
    xml_doc  = REXML::Document.new xml_file
    if type == "launchctl"
      fact   = []
      if param == "ProgramArguments"
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

def handle_readablefiles(type,kernel)
  fact = []
  if type != "readabledotfiles"
    file_name = type.gsub(/files/,"")
  end
  if file_name =~ /equiv/
    file_name = "hosts.equiv"
    home_dirs = [ '/etc' ]
  else
    file_name = "."+file_name
    home_dirs = %x[cat /etc/passwd |cut -f6 -d":" |grep -v "^/$" |grep -v '^#' |sort |uniq]
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
  else
    fact = ""
  end
  return fact
end

# Handle sudo type

def handle_sudo(kernel,modname,type,file_info,os_distro,os_version)
  file  = get_config_file(kernel,modname,type,os_distro,os_version)
  param = file_info[3]
  if File.exists?(file)
    fact = Facter::Util::Resolution.exec("cat #{file} |grep #{param}")
  end
  return fact
end

# Get user/application cron file

def get_user_crontab_file(kernel,modname,type,user_name)
  file_name = user_name+"crontabfile"
  fact_name = modname+"_"+kernel.downcase+"_"+file_name
  cron_file = Facter.value(fact_name)
  if cron_file !~ /[a-z]/
    cron_file = handle_crontabfile(kernel,type,file_name)
  end
  return cron_file
end

def handle_crontabfile(kernel,type,file_info)
  if type =~ /crontabfile/
    search_file = file_info[3].gsub(/crontabfile/,"")
  else
    search_file = file_info.gsub(/crontabfile/,"")
  end
  if kernel == "Linux"
    cron_dir = "/etc/cron.*/"
  end
  if kernel == "SunOS"
    cron_dir = "/var/spool/cron/crontabs/"
  end
  fact = Facter::Util::Resolution.exec("find #{cron_dir} -name #{search_file}")
  return fact
end

# Handle crontab

def get_user_crontab(kernel,modname,type,file_info)
  user = file_info[3]
  cron = get_user_cron_file(kernel,modname,type,user)
  fact = %x[sudo cat #{cron}]
  return fact
end

# Handle sshkeys

def handle_sshkeys(kernel,type)
  key_files = handle_sshkeyfiles(type)
  key_files = key_files.split(",")
  key_files.each do |key_file|
    if File.exist?(key_file)
      ssh_keys = %x[cat #{key_file}]
      fact     = fact.push(ssh_keys)
    end
  end
  fact = fact.join("\n")
  return fact
end

# Handle sshkeyfiles

def handle_sshkeyfiles(kernel,type)
  user_name = type.gsub(/sshkeyfiles/,"")
  if kernel == "Darwin" and user_name != "root"
    home_dir = "/Users/"+user_name
  else
    home_dir = %x[grep '#{user_name}:' /etc/passed |cut -f6 -d:].chomp
  end
  ssh_dir = home_dir+"/.ssh"
  if File.directory?(ssh_dir)
    fact = %x[find #{ssh_dir} -name "authorized_keys*"]
  end
  fact = fact.gsub(/\n/,",")
  return fact
end

# Handle primarygroup

def handle_primarygroup(type)
  gid  = handle_primarygid(type)
  fact = Facter::Util::Resolution.exec("cat /etc/group |grep ':#{gid}:' |cut -f1 -d:")
  return fact
end

# Handle primarygid

def handle_primarygid(type)
  user = type.gsub(/primarygroup/,"")
  fact = Facter::Util::Resolution.exec("cat /etc/passwd |grep '^#{user}:' |cut -f4 -d:")
  return fact
end

# Handle homedir

def handle_homedir(type)
  user = type.gsub(/homedir/,"")
  fact = Facter::Util::Resolution.exec("cat /etc/passwd |grep '^#{user}:' |cut -f6 -d:")
  return fact
end

# Handle env

def handle_env(type,file_info)
  user  = type.gsub(/env$/,"")
  if file_info[3]
    param = file_info[3..-1].join("_")
    fact = Facter::Util::Resolution.exec("sudo su - #{user} -c 'set' |grep '^#{param}'")
  else
    fact = %x[sudo su - #{user} -c 'set']
  end
  return fact
end

# Handle reserveduids

def handle_reserveduids()
  fact = %x[cat /etc/passwd | awk -F: '($3 < 100) { print $1 }']
  fact = fact.gsub(/\n/,"")
  return fact
end

# Handle userlist

def handle_userlist()
  fact = %x[cat /etc/passwd |cut -f1 -d:]
  fact = fact.gsub(/\n/,"")
  return fact
end

# Handle emptypasswordfields

def handle_emptypasswordfields()
  fact = %x[cat /etc/shadow |awk -F":" '{print $1":"$2":"}' |grep '::$' |cut -f1 -d:]
  fact = fact.gsub(/\n/,"")
  return fact
end

# Get bootdisk

def handle_bootdisk(kernel)
  case kernel
  when /Darwin/
    fact = %x[df |grep "/$" |awk '{print $1}'].chomp
    fact = File.basename(fact)
  end
  return fact
end

# Main code

if file_name !~ /template|operatingsystemupdate/
  if file_name =~ /_chsec_/
    file_name = file_name.gsub(/_chsec_/,"_lssec_")
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
        when /env$/
          fact = handle_env(type,file_info)
        when /bootdisk/
          fact = handle_bootdisk(kernel)
        when "emptypasswordfields"
          fact = handle_emptypasswordfields()
        when "userlist"
          fact = handle_userlist()
        when "reserveduids"
          fact = handle_reserveduids()
        when /primarygroup/
          fact = handle_primarygroup(type)
        when /primarygid/
          fact = handle_primarygid(type)
        when /homedir/
          fact = handle_homedir(type)
        when /sshkeyfiles/
          fact = handle_sshkeyfiles(type)
        when /sshkeys/
          fact = handle_sshkeys(type)
        when /rhostsfiles|shostsfiles|hostsequivfiles|netrcfiles|readabledotfiles/
          fact = handle_readablefiles(type,kernel)
        when "symlink"
          fact = handle_symlink(file_info)
        when /cron$/
          fact = handle_cron(kernel,type)
        when "crontab"
          fact = get_user_crontab(kernel,modname,type,user_name)
        when /^nis/
          fact = handle_nis(type)
        when /groupmembers/
          fact = handle_groupmembers(type)
        when /xml|plist|launchctl/
          fact = handle_xml_types(type,file_info)
        when /syslog/
          fact = handle_syslog(kernel,modname,type,file_info,os_distro,os_version)
        when /byothers|byeveryone/
          fact = handle_readwrite(type,file_info)
        when /directorylisting/
          fact = handle_directorylisting(type,file_info)
        when "inactivewheelusers"
          fact = handle_inactivewheelusers()
        when "sudo"
          fact = handle_sudo(kernel,modname,type,file_info,os_distro,os_version)
        when /ssh$|krb5$|hostsallow$|hostsdeny$|snmp$|sendmail$|ntp$|aliases$|grub$|selinux$|cups$|apache$/
          fact = get_param_value(kernel,modname,type,file_info,os_distro,os_version)
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
          fact = handle_services(kernel,type,os_distro)
        when /duplicate/
          fact = handle_duplicate(type,file_info)
        when /configfile/
          fact = handle_configfile(kernel,type,file_info,os_distro,os_version)
        when /crontabfile/
          fact = handle_crontabfile(kernel,type,file_info)
        when "pam"
          fact = handle_pam(kernel,type,file_info,os_version)
        when "file"
          fact = handle_file(kernel,modname,type,subtype,file_info)
        end
        case kernel
        when "Linux"
          fact = handle_linux(kernel,modname,type,file_info,fact,os_version)
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
