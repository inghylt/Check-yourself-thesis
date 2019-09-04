nginx_params = yaml(content: inspec.profile.file('params.yml')).params

forbidden_modules = nginx_params['forbidden-modules']
weekly_log_rotation = nginx_params['weekly-log-rotation']
memory_zone_name = nginx_params['memory-zone-name']
memory_zone_value = nginx_params['memory-zone-value']
request_per_second_per_IP = nginx_params['requests-per-second-per-IP']
burst_limit = nginx_params['burst-limit']
top_level_domain_name = nginx_params['top-level-domain-name']
preload_check = nginx_params['preload-check']
hardcoded_boo_boos = nginx_params['hardcoded-boo-boos']


#example of how the code can be adapted to suit a variety of operating systems
if os.debian?
  package_info_command = 'apt show nginx'
  index_distance = 1
  version_string = 'Version:'
end

if os.redhat?
  package_info_command = 'yum info nginx'
  index_distance = 2
  version_string = 'Version'
end

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

control 'Verify That Nginx Is Installed' do
  impact 1.0
  title '1.1.1 Ensure NGINX is installed'
  desc 'Ensure that Nginx is installed'
   describe nginx.version do
    it { should cmp > '0' }
  end
end

if nginx.version.to_i > 0

  control 'Verify That the Latest Software Package Is Installed' do
    impact 0.5
    title '1.2.2 Ensure the latest software package is installed'
    desc 'Up-to-date software provides the best possible protection against exploitation of security
vulnerabilities, such as the execution of malicious code.'
        #Obtaining the latest version number available
        result_array = command(package_info_command).stdout.split
        index_of_version_string = result_array.find_index(version_string).to_i
        index_of_version_number = index_of_version_string + index_distance
        version = result_array[index_of_version_number]
        version_number = version.split('-')[0]

        #Comparing the current number with the latest
        describe nginx.version do
          it { should cmp version_number }
        end
      
  end



  control 'Verify Non-Existence of Module' do                        
    impact 1.0                                
    title 'Benchmark 2.1.1, 2.1.2, 2.1.3, 2.1.4'
    desc 'These modules should not be installed, see CIS NGINX Benchmark Chapter 2 for more information'
    describe nginx do
      forbidden_modules.each do |forbidden_module|           
      	its ('modules') { should_not include forbidden_module }
    	end
    end
  end



  control 'Verify That Nginx Use a Non-Privileged and Dedicated Service Account' do
    impact 0.5
    title '2.2.1 Ensure that NGINX is run using a non-privileged, dedicated service
  account'
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

      #assuming that it the user should not belong to any other groups than the primary group
      describe nginx_user_groups_string do
        it { should cmp nginx_user }
      end
    end
  end



  control 'Verify That the Nginx Service Account Is Locked' do 
    impact 1.0
    title '2.2.2 Ensure the NGINX service account is locked'
    desc "As a defense-in-depth measure, the nginx user account should be locked to prevent logins
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



  control 'Verify Correct Ownership' do
  	impact 1.0
  	title '2.3.1 Ensure NGINX directories and files are owned by root'
  	desc 'Setting ownership to only those users in the root group and the root user will reduce the likelihood of unauthorized modifications to the nginx configuration files, see CIS NGINX Benchmark 2.3.1 for more information'
  	
  	nginx_files_and_dir = command('find /etc/nginx -print').stdout.split
  	nginx_files_and_dir.each do |file|
    	describe file(file) do
    		its('owner') {should eq 'root'}
    		its('group') {should eq 'root'}
      end
    end
  end



  control 'Verify Correct Permission' do 
    impact 1.0
    title '2.3.2 Ensure access to NGINX directories and files is restricted'
    desc 'Permissions on the /etc/nginx directory should enforce the principle of least privilege'
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

    nginx_files = command('find /etc/nginx -type f').stdout.split
    nginx_files.each do |file|
      describe file(file) do
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



  control 'Verify That the Nginx Process ID (PID) File Is Secured' do
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



  control'Verify Non-Existence of Directive or Existence of Correct Configuration' do
    impact 0.5
    title '2.3.4 Ensure the core dump directory is secured'
    desc 'Core dumps may contain sensitive information that should not be accessible by other
    accounts on the system.' 
    describe nginx_conf.params do
      it { should_not include 'working_directory' }
    end

    if nginx_conf.params.has_key?('working_directory') and nginx_conf.params.include?('user')

      working_directory_location = nginx_conf.params.fetch('working_directory').flatten[0]

      root_path_array = []

      #Get potential root paths in http context
      if nginx_conf.params.fetch('http')[0].include?('root')
        root_path_array.push(nginx_conf.params.fetch('http')[0].fetch("root").flatten[0])
      end
      #Get potential root paths in server context
      nginx_conf.servers.each do |element|
        if element.params.include?('root')
          root_path_array.push(element.params.fetch('root').flatten[0])
        end
      end

      #Get potential root paths in location context
      nginx_conf.locations.each do |element|
        if element.params.include?('root')
          root_path_array.push(element.params.fetch('root').flatten[0])
        end
      end

      nginx_user_groups = command('groups ' + nginx_user).stdout.split.uniq

      #remove colon to only keep groups
      index_of_element_to_remove = nginx_user_groups.index(":")
      nginx_user_groups.delete_at(index_of_element_to_remove)
      nginx_user_groups_string = nginx_user_groups.join(', ')

      root_path_array.each do |path|
        describe file(working_directory_location) do
          its('path') { should_not include path}
        end
      end
        
      describe file(working_directory_location) do
        its('owner') { should eq 'root' }
        its('group') { should be_in nginx_user_groups_string }
        it { should_not be_readable.by('others') }
        it { should_not be_writable.by('others') }
        it { should_not be_executable.by('others') }
      end
    end
  end

  control 'Verify Non-Existence of Directive or Text' do
    impact 1.0
    title 'OWASP-12, Check If Password or Encryption Keys Is Hardcoded In The Source Code or Configuration Files'
    desc 'Passwords and keys should not be stored in configuration files as this might lead to their unintended exposure'
    
    hardcoded_boo_boos.each do |boo|
      describe command("grep -R '" + boo + "' /etc/nginx/").stdout do
        it { should_not include boo }
      end
    end
  end



  control 'Verify Existence of Directive and Verify Its Value' do
    impact 1.0
    title '3.3 Ensure error logging is enabled and set to the info logging level'
    desc "Error logging can be useful in identifying an attacker attempting to exploit a system and
  recreating an attacker's steps. Error logging also helps with identifying possible issues with
  an application."
    describe parse_config(nginx_parsed_config, options) do
      its ('error_log') { should include 'info' }
    end
  end



  control 'Verify Existence of Directive Inside a Context and Verify Its Value-01' do
    impact 1.0
    title '2.5.1 Ensure server_tokens directive is set to `off`'
    desc 'Attackers can conduct reconnaissance on a website using these response headers, then
target attacks for specific known vulnerabilities associated with the underlying
technologies. Hiding the version will slow down and deter some potential attackers.'
    describe parse_config(nginx_parsed_config, options).server_tokens do
      it { should cmp 'off' }
    end
  end



  control 'Verify Existence of Directive Inside a Context and Verify Its Value-02' do
    impact 0.5
    title '2.5.3 Ensure hidden file serving is disabled'
    desc 'Disabling hidden files prevents an attacker from being able to reference a hidden file that
    may be put in your location and have sensitive information, like .git files.'
    locations_array = nginx_conf.locations

    describe locations_array.join(',') do
       it { should include '~ /\\\\.'} 
    end

    if locations_array.join(',').include?('~ /\\\\.')
      locations_array.each do |element|
        if element.params.values.flatten.include?("/\\.")
          describe element.params do
            it { should include "deny"=>[["all"]] }
            it { should include "return"=>[["404"]] }
          end
        end
      end
    end
  end



  control 'Verify Existence of Directive Inside a Context and Verify Correct Configuration of the Value' do
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
        if element.params.include?('ssl_dhparam')
          dhparam_path = element.params.fetch('ssl_dhparam').flatten[0]
          oppenssl_dhparam_result = command('openssl dhparam -inform PEM -in ' + dhparam_path + ' -check -text')
          #Create an array with "DH Parameters: (NUMBER bit)"" on index 0, create new array with "(NUMBER" on index 0
          oppenssl_dhparam_result_only_parameters_unclean= oppenssl_dhparam_result.stdout.split(')')[0].split.delete_if { |result| result.include?("DH") || result.include?("Parameters") }
          #Create new array with "NUMBER" on index 1
          oppenssl_dhparam_result_only_parameters_clean = oppenssl_dhparam_result_only_parameters_unclean[0].split('(')
          describe oppenssl_dhparam_result_only_parameters_clean[1] do
            it { should cmp > '2047' }
          end
        end
      end
    end



  control 'Verify Existence of Directives and Nested Directivies Inside a Context and Verify Their Values' do
      impact 0.5
      title '5.2.5 Ensure rate limits by IP address are set'
      desc 'Rate limiting allows you to mitigate potential denial of service attacks as a defense in depth
  mechanism.'
      http_entries = nginx_conf.http.entries
      http_entries.each do |element|
        describe element.params do
          it { should include "limit_req_zone"=>[["$binary_remote_addr", "zone=" + memory_zone_name + ":" + memory_zone_value, "rate=" + request_per_second_per_IP + 'r/s']] }
        end
      end

      locations_array = nginx_conf.http.locations
      locations_array.each do |element|
        if element.params.has_value?(["/"])
          describe element.params do
            it { should include "limit_req"=>[["zone=" + memory_zone_name, "burst=" + burst_limit, "nodelay"]] }
          end
        end
      end
    end



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



  control 'Verify That Default Content Is Disabled' do
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



  control 'Verify Correct Configuration Through HTTP Request' do
    impact 0.5
    title '4.1.12 Ensure your domain is preloaded'
    desc 'Preloading your domain helps prevent HTTP downgrade attacks and increases trust. Note: Preloading should only be done with careful consideration!'
    desc 'Your website and all its subdomains will be forced over HTTPS. If your website or any of its subdomains are not able to support preloading, 
    you should not preload your site. Preloading should be opt-in nly, and if done, may impact more sites than the nginx instance you are working on.
    Removing preloading can be slow and painful, and should only be done with careful consideration according to https://hstspreload.org.'

    if preload_check=='true'
      preload_status_response_array = command('curl https://hstspreload.org/api/v2/status?domain=' + top_level_domain_name).stdout.split(',')
      status_value_separated_array = preload_status_response_array[1].split(': ')
      describe status_value_separated_array[1] do
        it { should include "preloaded" }
      end
    end
  end



  
  
end



