nginx_params = yaml(content: inspec.profile.file('params.yml')).params

forbidden_modules = nginx_params['forbidden-modules']

weekly_log_rotation = nginx_params['weekly-log-rotation'].to_s

nginx_parsed_config = command('nginx -T').stdout

if nginx_conf.params.include?("user")
  nginx_user = nginx_conf.params.fetch("user").flatten[0]
end

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/
}

options_add_header = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
  multiple_values: true
}
# you add controls here
control 'verify-modules' do                        # A unique ID for this control
  impact 1.0                                # The criticality, if this control fails.
  title 'Verify that certain modules are not installed' # A human-readable title
  desc 'These modules should not be installed, see CIS NGINX Benchmark Chapter 2 for more information'
  describe nginx do
    forbidden_modules.each do |forbidden_module|           # The actual test
    	its ('modules') { should_not include forbidden_module }
  	end
  end
end

control 'verify-ownership' do
	impact 1.0
	title 'Verify that owner and group of the /etc/nginx directory and its files is root'
	desc 'Setting ownership to only those users in the root group and the root user will reduce the likelihood of unauthorized modifications to the nginx configuration files, see CIS NGINX Benchmark 2.3.1 for more information'
	
	nginx_files_and_dir = command('find /etc/nginx -print').stdout.split
	nginx_files_and_dir.each do |file|
  	describe file(file) do
  		its('owner') {should eq 'root'}
  		its('group') {should eq 'root'}
    end
  end
end

control 'verify-permissions-01' do 
  impact 1.0
  title 'Verify that access to NGINX directories is restricted'
  desc 'Permissions on the /etc/nginx directory should enforce the principle of least privilege, see CIS NGINX Benchmark 2.3.2'
  nginx_directories = command('find /etc/nginx -type d').stdout.split
  nginx_directories.each do |dir|
    describe file(dir) do
      it { should be_readable.by('owner') }
      it { should be_writable.by('owner') }
      it { should be_executable.by('owner') }
      it { should be_readable.by('group') }
      it { should_not be_writable.by('group') }
      it { should be_executable.by('group') }
      it { should_not be_readable.by('others') }
      it { should_not be_writable.by('others') }
      it { should_not be_executable.by('others') }
    end
  end
end

control 'verify-permissions-02' do 
  impact 1.0
  title 'Verify that access to NGINX files is restricted'
  desc 'Permissions on the /etc/nginx directory should enforce the principle of least privilege, see CIS NGINX Benchmark 2.3.2'
  nginx_directories = command('find /etc/nginx -type f').stdout.split
  nginx_directories.each do |dir|
    describe file(dir) do
      it { should be_readable.by('owner') }
      it { should be_writable.by('owner') }
      it { should_not be_executable.by('owner') }
      it { should be_readable.by('group') }
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('group') }
      it { should_not be_readable.by('others') }
      it { should_not be_writable.by('others') }
      it { should_not be_executable.by('others') }
    end
  end
end

control 'Ändra titel' do
  impact 1.0 
  title 'test'
  desc 'test'
  describe parse_config(nginx_parsed_config, options_add_header) do
    its('add_header') { should include 'Strict-Transport-Security "max-age=15768000;"' }
  end
end

control 'Locationstest' do
  impact 1.0
  title 'test2'
  desc 'test2'
  locations_array = nginx_conf.locations
  locations_array.each do |element|
    if element.params.has_value?(["/"])
      describe element.params do
        it { should include "limit_req"=>[["zone=ratelimit", "burst=10", "nodelay"]] }
      end
    end
  end
end

control 'httpTest' do
  impact 1.0
  title 'test3'
  desc 'test3'
  http_entries = nginx_conf.http.entries
  http_entries.each do |element|
    describe element.params do
      it { should include "limit_req_zone"=>[["$binary_remote_addr", "zone=ratelimit:10m", "rate=5r/s"]] }
    end
  end
end

control 'combine locations and http' do
  title 'test4'
  desc 'test4'
  http_entries = nginx_conf.http.entries
  http_entries.each do |element|
    describe element.params do
      it { should include "limit_req_zone"=>[["$binary_remote_addr", "zone=ratelimit:10m", "rate=5r/s"]] }
    end
  end

  locations_array = nginx_conf.http.locations
  locations_array.each do |element|
    if element.params.has_value?(["/"])
      describe element.params do
        it { should include "limit_req"=>[["zone=ratelimit", "burst=10", "nodelay"]] }
      end
    end
  end
end

control'Ensure Non-Existance of Directive or Existance of Correct Configuration' do
  impact 1.0
  title 'Ensure the core dump directory is secured (Not Scored)'
  desc 'Core dumps may contain sensitive information that should not be accessible by other
  accounts on the system.' 
  describe.one do
    describe nginx_conf.params do
      it { should_not include "working_directory" }
    end

    if nginx_conf.params.has_key?("working_directory") and nginx_conf.params.include?("user")

      working_directory_location = nginx_conf.params.fetch("working_directory").flatten[0]

      nginx_user_groups = command('groups ' + nginx_user).stdout.split.uniq

      #remove colon to only keep groups
      index_of_element_to_remove = nginx_user_groups.index(":")
      nginx_user_groups.delete_at(index_of_element_to_remove)
      nginx_user_groups_string = nginx_user_groups.join(', ')

      describe file(working_directory_location) do
        its('owner') { should eq 'root'}
        its('group') { should be_in nginx_user_groups_string }
        it { should_not be_readable.by('others') }
        it { should_not be_writable.by('others') }
        it { should_not be_executable.by('others') }
      end
    end
  end
end

control 'Disable Default Content' do
  impact 1.0
  title 'CIS 2.5.2 Ensure default error and index.html pages do not reference NGINX'
  desc 'By gathering information about the server, attackers can target attacks against its known
vulnerabilities. Removing pages that disclose the server runs NGINX helps reduce targeted
attacks on the server.'
  if File.file?('/usr/share/nginx/html/index.html')
    describe file('/usr/share/nginx/html/index.html') do
      its ('content') { should_not include 'nginx' }
    end
  end

  if File.file?('/usr/share/nginx/html/50x.html')
    describe file ('/usr/share/nginx/html/50x.html') do
      its ('content') { should_not include 'nginx' }
    end
  end
end

control 'Verify Existence of Directive' do
  impact 1.0
  title '4.1.6 Ensure custom Diffie-Hellman parameters are used (Scored)'
  desc 'Backward-compatible Perfect Forward Secrecy (PFS) ciphers (e.g. DHE-RSA-AES128-
SHA256) should use strong and unique parameters. By default, NGINX will generate 1024-
bit RSA keys for PFS ciphers; stronger alternatives should be used instead to provide better
protection for data protected by encryption.'

  http_servers = nginx_conf.http.servers
  http_servers.each do |element|
    describe element.params do
      it { should include 'ssl_dhparam' }
    end
  end
end


control 'Verify that the NGINX service account is locked' do
  impact 1.0
  title '2.2.1 Ensure that NGINX is run using a non-privileged, dedicated service
account (Not Scored)'
  desc 'Running a web server under a non-privileged, dedicated service account helps mitigate the
risk of lateral movement to other services or processes in the event the user account
running the web services is compromised. The default user nobody is typically used for
several processes, and if this is compromised, it could allow an attacker to have access to all
processes running as that user.'
  describe nginx_conf.params.keys do
    it { should include "user" }
  end

  if nginx_conf.params.include?("user")

    describe command('sudo -l -U ' + nginx_user).stdout do
      it { should include "is not allowed to run sudo" }
    end

    #use uniq to remove user in user : groupA groupB
    nginx_user_groups = command('groups ' + nginx_user).stdout.split.uniq

    #remove colon to only keep groups
    index_of_colon = nginx_user_groups.index(":")
    nginx_user_groups.delete_at(index_of_colon)
    nginx_user_groups_string = nginx_user_groups.join(', ')

    describe nginx_user_groups_string do
      it { should cmp nginx_user }
    end
  end
end

control '2.2.2 Ensure the NGINX service account is locked (Scored)' do 
  impact 1.0
  title "2.2.2 Ensure the NGINX service account is locked'
  desc 'As a defense-in-depth measure, the nginx user account should be locked to prevent logins
  and to prevent someone from switching users to nginx using the password. In general,
  there shouldn't be a need for anyone to have to su as nginx, and when there is a need, sudo
  should be used instead, which would not require the nginx account password."

  describe nginx_conf.params.keys do
    it { should include "user" }
  end
   if nginx_conf.params.include?("user")
    passw_status_result = command('passwd -S ' + nginx_user).stdout.split

    #remove user to remove potential L:s
    index_of_user = passw_status_result.index(nginx_user)
    passw_status_result.delete_at(index_of_user)
    passwd_status_result_string = passw_status_result.join(', ')
     describe passwd_status_result_string do
      it { should include 'L' }
      end
    end
end

control 'Verify that the NGINX Service Account Has an Invalid Shell' do
impact 1.0
title '2.2.3 Ensure the NGINX service account has an invalid shell (Scored)'
desc 'The account used for nginx should only be used for the nginx service and does not need to
have the ability to log in. This prevents an attacker who compromises the account to log in
with it.'

describe nginx_conf.params.keys do
    it { should include "user" }
  end
   if nginx_conf.params.include?("user")
    grep_passwd_result = command('grep ' + nginx_user + ' /etc/passwd').stdout
    describe grep_passwd_result do
      it { should include "/sbin/nologin"}
    end
  end
end

control 'Verify that the nGINX process Id (PID) file is secured' do
  impact 1.0
  title '2.3.3 Ensure the NGINX process ID (PID) file is secured (Scored)'
  desc 'The PID file should be owned by root and the group root. It should also be readable to
everyone, but only writable by root (permissions 644). This will prevent unauthorized
modification of the PID file, which could cause a denial of service.'
  pid_path= nginx_conf.params.fetch("pid").flatten[0]

  describe file (pid_path) do
    its('owner') {should eq 'root'}
    its('group') {should eq 'root'}
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should_not be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
end

control 'Verify That Log Files Are Rotated' do
  impact 1.0
  title '3.4 Ensure log files are rotated'
  desc 'Log files are important to track activity that occurs on your server, but they take up
  significant amounts of space. Log rotation should be configured in order to ensure the logs
  do not consume so much disk space that logging becomes unavailable.'

  describe file('/etc/logrotate.d/nginx') do
    its('content') { should include 'weekly' }
    its('content') { should include 'rotate ' + weekly_log_rotation }
  end
end

#nginx_option_V_pid = command('nginx -V').stdout.split.keep_if { |result| result.include?("pid") }
# control 'verify non-existence of working_directory' do

control 'Ensure Directive and Verify That Its Value Is Lower/Higher than Threshold' do
  impact 1.0
  title '2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0'
  desc 'Setting a keep-alive timeout on the server side helps mitigate denial of service attacks that
  establish too many persistent connections, exhausting server resources.'
  describe parse_config(nginx_parsed_config, options).keepalive_timeout.to_i do
    it { should be < 11 }
    it { should be > 0 }
  end
end


#   #describe.one do
#     describe nginx_conf.params do
#       it { should_not include "working_directory" }
#     end
# end

# control 'verify correct setting on working_directory file' do 
#   if nginx_conf.params.has_key?("working_directory")

#     working_directory_location = nginx_conf.params.fetch("working_directory").flatten[0]

#     nginx_user = nginx_conf.params.fetch("user").flatten[0]

#     nginx_user_groups = command('groups ' + nginx_user).stdout.split.uniq
#     index_of_element_to_remove = nginx_user_groups.index(":")
#     nginx_user_groups.delete_at(index_of_element_to_remove)
#     nginx_user_groups_string = nginx_user_groups.join(', ')

#     describe file(working_directory_location) do
#       its('owner') { should eq 'root'}
#       its('group') { should be_in nginx_user_groups_string }
#       it { should_not be_readable.by('others') }
#       it { should_not be_writable.by('others') }
#       it { should_not be_executable.by('others') }
#     end
#   end  
    # describe ConfigurationB do
    #   its('setting_2') { should eq true }
    # end
  #end
#end



 



# control 'non-existence or correct configuration' do
#   impact 1.0
#   title 'test'
#   desc 'test'
#   describe file('/etc/nginx/nginx.conf') do
#     its('content') {should_not match 'http'}
#   end
# end

# control 'Ensure Directive and Verify Its Value' do
#   impact 1.0
#   title 'test'
#   desc 'test'
#   describe parse_config(nginx_parsed_config, options) do
#     its('return') { should eq '404' }
#     its('listen') { should eq '443' }
#   end
# end

# control 'tes2' do
#   impact 1.0
#   title 'test'
#   desc 'test'
#   describe parse_config(nginx_parsed_config, options) do
#     its('location /') { should include 'test' }
#   end
# end



