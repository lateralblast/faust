# Name:         faust (Facter Automatic UNIX Symbolic Template)
# Version:      0.0.2
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
# ln -s faust_template.rb faust_linux_enableservices.rb
#
# To check the value of a parameter in a file, eg TIMESYNC in
# /private/etc/hostprofile on OS X:
#
# ln -s faust_template.rb faust_darwin_file_private_etc_host_config_parameter_TIMESYNC.rb
#
# Refer to http://github.com/richardatlateralblast/faust

require 'facter'

# Get file name for processing

file_name = __FILE__
file_name = File.basename(file_name,".*")

# Doing file system searches takes time
# Only enable it if it's needed

fs_search = "no"

if file_name !~ /template/
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
  if type == "lssec"
    sec_file   = file_info[3]
    sec_stanza = file_info[4]
    parameter  = file_info[5]
  end
  if type =~ /pwpolicy|file|defaults|dscl|pmset|trustchk/
    subtype   = file_info[3]
  end
  if type =~ /dscl|defaults/
    parameter = file_info[4]
  end
  if f_kernel == "all" or f_kernel == kernel
    if f_kernel == "all"
      file_info[1] = kernel
      fact_name    = file_info.join("_")
    else
      fact_name = file_name
    end
    Facter.add(fact_name) do
      if f_kernel != "all"
        confine :kernel => f_kernel
      end
      setcode do
        fact   = ""
        os_version = Facter.value("operatingsystemrelease")
        if type =~ /rhostfiles|netrcfiles|readabledotfiles/
          file_name = type.gsub(/files/,"")
          file_name = "."+file_name
          home_dirs = %x[cat /etc/passwd |cut -f6 -d":" |grep -v "^/$"]
          home_dirs = home_dirs.split(/\n/)
          home_dirs.each do |home_dir|
            if File.directory?(home_dir)
              if type == "readabledotfiles"
                files_list = %x[sudo find #{home_dir} -name .\[A-z,0-9\]* -maxdepth 1 -type f ! -perm 600]
                files_list = files_list.split(/\n/)
                files_list.each do |check_file|
                  if File.exists?(check_file)
                    fact.push(check_file)
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
        end
        if type == "unownedfiles" and fs_search == "yes"
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
        end
        if type == "worldwritablefiles" and fs_search == "yes"
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
        end
        if type == "inactivewheelusers"
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
        end
        if type == "groupexists"
          group_name  = file_info[3]
          group_check = %x[cat /etc/group |grep '^#{group_name}:']
          if group_check =~ /[A-z]/
            fact = "yes"
          else
            fact = "no"
         end
        end
        if type == "invalidshells"
          fact = %x[cat /etc/passwd | grep -v '^#' |awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false" ) {print $1}']
          fact = fact.split("\n")
          fact = fact.join(",")
        end
        if type == "exec"
          exec = file_info[3..-1].join(" ")
          exec = exec.gsub(/pipe/,"|")
          fact = Facter::Util::Resolution.exec("#{exec} 2>&1 |sed 's/ $//g'")
        end
        if type == "mtime"
          fs_item = file_info[3..-1]
          fs_item = "/"+fs_item.join("/")
          fact    = (Time.now - File.stat(fs_item).mtime).to_i / 86400.0
          fact    = fact.to_i.to_s
        end
        if type == "trustchk"
          fact = Facter::Util::Resolution.exec("/usr/sbin/trustchk -p #{subtype} 2>&1 |cut -f2 -d=")
        end
        if type == "perms"
          fs_item = file_info[3..-1]
          fs_item = "/"+fs_item.join("/")
          mode    = File.stat(fs_item).mode
          mode    = sprintf("%o",mode)[-4..-1]
          uid     = File.stat(fs_item).uid.to_s
          gid     = File.stat(fs_item).gid.to_s
          user    = %x[cat /etc/passwd |awk -F: '{if ($3 == #{uid}) print $1}'].chomp
          group   = %x[cat /etc/group |awk -F: '{if ($3 == #{gid}) print $1}'].chomp
          fact    = mode+","+user+","+group
        end
        if type == "pmset"
          fact = Facter::Util::Resolution.exec("pmset -g |grep '#{subtype}' |awk '{print $2}' |sed 's/ //g'")
        end
        if type == "dscl"
          if subtype != "root"
            subtype = subtype.capitalize
          end
          fact = Facter::Util::Resolution.exec("dscl . -read /Users/#{subtype} #{parameter} 2>&1 |awk -F: '{print $(NF)}' |sed 's/ //g'")
        end
        if type == "dotfiles"
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
        end
        if type == "installedpackages"
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
        end
        if type == "inetd"
          if File.exists?("/etc/inetd.conf")
            fact = %x[cat /etc/inetd.conf | grep -v '^#' | awk '{print $1}']
            fact = fact.split("\n")
            fact = fact.join(",")
          end
        end
        if type == "inittab"
          if kernel == "AIX"
            fact = %x[cat /etc/inittab |grep -v '^#' |cut -f1 -d:]
          else
            fact = %x[lsitab -a |grep -v '^#' |cut -f1 -d:]
          end
          fact = fact.gsub(/\n/,",")
        end
        if type == "rctcp"
          fact = %x[cat /etc/rc.tcpip |grep -v '^#' |awk '{print $2}']
          fact = fact.gsub(/\n/,",")
        end
        if type == "services"
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
          fact = fact.gsub(/\n/,",")
        end
        if type == "managednode"
          fact = Facter::Util::Resolution.exec("pwpolicy -n -getglobalpolicy 2>&1")
          if fact =~ /Error/
            fact = "/Local/Default"
          end
        end
        if type =~ /duplicate/
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
        end
        if type == "ndd"
          if os_version =~ /10/
            driver    = "/dev/"+file_info[3]
            parameter = file_info[4..-2].join("_")
            if parameter == "tcp_extra_priv_ports_add"
              fact = Facter::Util::Resolution.exec("ndd -get #{driver} tcp_extra_priv_ports #{parameter}")
            else
              fact = Facter::Util::Resolution.exec("ndd -get #{driver} #{parameter}")
            end
          end
        end
        if type == "ipadm"
          if os_version =~ /11/
            driver    = file_info[3]
            parameter = "_"+file_info[4..-2].join("_")
            fact = Facter::Util::Resolution.exec("ipadm show-prop #{driver} -co current #{parameter}")
          end
        end
        if type =~ /configfile/
          if type =~ /apache/
            search_file = "httpd.conf"
          end
          config_file = ""
          if config_file !~ /[A-z]/
            config_file_list = []
            dir_list = [ '/etc' '/etc/sfw', '/etc/apache', '/etc/apache2',
                         '/usr/local/etc', '/usr/sfw/etc', '/opt/sfw/etc' ]
            dir_list.each do |dir_name|
              config_file=dir_name+"/"+search_file
              if File.exists?(config_file)
                config_file_list.push(config_file)
              end
            end
            fact = config_file_list[0]
          end
        end
        if type == "defaults"
          fact = Facter::Util::Resolution.exec("defaults read /Library/Preferences/#{subtype} #{parameter} 2>&1 |grep -v default |sed 's/ $//g'")
        end
        if type == "lssec"
          fact = Facter::Util::Resolution.exec("lssec -f #{sec_file} -s #{sec_stanza} -a #{parameter} 2>&1 |awk '{print $2}' |cut -f2 -d=")
        end
        if type == "inetadm"
          file_info = file_info[3..-1].join("_")
          if file_info =~ /parameter/
            (service_name,parameter) = file_info.split("_parameter_")
            service_name = service_name.gsub(/_/,"/")
            fact = Facter::Util::Resolution.exec("inetadm -l #{service_name} |grep #{parameter} |cut -f2 -d=")
          end
        end
        if type == "file"
          separator = " "
          comment   = "#"
          file_info = file_info[3..-1].join("_")
          if file_info =~ /parameter/
            (config_file,parameter) = file_info.split("_parameter_")
            parameter = parameter.gsub(/_star_/,"\*")
            parameter = parameter.gsub(/_bang_/,"\!")
            parameter = parameter.gsub(/_/," ")
            if config_file =~ /^system|^apache/
              if config_file =~ /system/
                config_file = "/etc/system"
                parameter   = parameter.gsub(/\./,':')
              end
              if config_file =~ /apache/
                config_file = modname+"_"+kernel.downcase+"_"+subtype+"configfile"
                config_file = Facter.value(config_file)
              end
            else
              config_file = config_file.gsub(/^_/,"")
              config_file = config_file.gsub(/_/,"/")
              config_file = "/"+config_file
            end
            if config_file =~ /hostconfig/
              separator = "="
            end
            if config_file =~ /hosts\.allow|hosts\.deny/
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
                config_file = modname+"_"+subtype+"configfile"
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
        end
        if type == "pwpolicy"
          managednode = Facter.value("#{modname}_darwin_system_managednode")
          fact = Facter::Util::Resolution.exec("pwpolicy -n #{managednode} -getglobalpolicy #{subtype} 2>&1 |cut -f2 -d= |sed 's/ //g'")
       end
        if fact !~ /[0-9]|[A-z]/
          fact = ""
        end
        fact
      end
    end
  end
end
