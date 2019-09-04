# encoding: utf-8
# copyright: 2018, The Authors

params = yaml(content: inspec.profile.file('params.yml')).params
forbidden_modules = params['forbidden-modules']
host_name = params['host-name']

if os.debian?
  loaded_modules_command = 'apache2ctl -M'
  apache_name = 'apache2'
end

#Obtaining the user
if apache_conf.params.include?('User')
	if apache_conf.params.fetch('User')[0].include?('${')
			#Obtaining the value of User stated in the envvars file
			env_name=apache_conf.params.fetch('User')[0].split('{')[1].split('}')[0]
			envvars_array = file(File.join(apache_conf.conf_dir, 'envvars')).content.split
			env_name_and_value = ''
			envvars_array.each do |element|
				if element.include?(env_name)
					env_name_and_value = element
				end
			end

			user = env_name_and_value.split('=')[1]
	else user = apache_conf.params.fetch('User')[0]
	end

else user = ''
end


control 'Verify Existance of Module' do 
	impact 1.0
	title '7.1 Install mod_ssl and/or mod_nss'
	desc "It is best to plan for SSL/TLS implementation from the beginning of any new web server. As
	most web servers have some need for SSL/TLS due to:
	• Non-public information submitted that should be protected as it's transmitted to the web
	server.
	• Non-public information that is downloaded from the web server.
	• Users are going to be authenticated to some portion of the web server
	• There is a need to authenticate the web server to ensure users that they have reached the
	real web server and have not been phished or redirected to a bogus site."

	loaded_modules = command(loaded_modules_command).stdout.split.inspect

	describe. one do
		describe loaded_modules do
			it { should include 'ssl_module'}
		end

		describe loaded_modules do
			it { should include 'nss_module' }
		end
	end
end

control 'Disable modules' do
	impact 1.0
	title '2.6 Disable Proxy Modules'
	desc 'Proxy servers can act as an important security control when properly configured, however a
secure proxy server is not within the scope of this benchmark. A web server should be primarily
a web server or a proxy server but not both, for the same reasons that other multi-use servers are
not recommended. Scanning for web servers that will also proxy requests is a very common
attack, as proxy servers are useful for anonymizing attacks on other servers, or possibly proxying
requests into an otherwise protected network.'
	loaded_modules = command(loaded_modules_command).stdout.split.inspect
	describe loaded_modules do
      forbidden_modules.each do |forbidden_module|           # The actual test
      	it{ should_not include forbidden_module }
    	end
	end
end

control 'Run the Apache Web Server as a non-root user' do
	impact 1.0
	title '3.1 Run the Apache Web Server as a non-root user'
	desc 'One of the best ways to reduce your exposure to attack when running a web server is to create a
	unique, unprivileged user and group for the server application. The nobody or daemon user and
	group that comes default on Unix variants should NOT be used to run the web server, since the
	account is commonly used for other separate daemon services. Instead, an account used only by
	the apache software so as to not give unnecessary access to other services. Also, the identifier
	used for the apache user should be a unique system account. System user accounts UID numbers
	have lower values which are reserved for the special system accounts not used by regular users,
	such as discussed in User Accounts section of the CIS Red Hat benchmark. Typically, system
	accounts numbers range from 1-999 , or 1-499 and are defined in the /etc/login.defs file.
	As an even more secure alternative, if the Apache web server can be run on high unprivileged
	ports, then it is not necessary to start Apache as root , and all of the Apache processes may be
	run as the Apache specific user as described below.'

	describe apache_conf.params.keys do 
		it { should include 'User' }
		it { should include 'Group' }
	end

	#Obtaining uid for user
	uid_info = command('id ' + user).stdout.split[0]
	uid_user_number = uid_info.split('=')[1].split('(')[0]

	#Obtainging uid_min in /etc/login.defs
	uid_min_number = command("grep '^UID_MIN' /etc/login.defs").stdout.split[1]

	describe uid_user_number do
		it { should cmp< uid_min_number }
	end

	ps_aux_apache_user = command("ps aux | grep " + apache_name + " | grep -v '^root'").stdout.split[0]

	describe ps_aux_apache_user do
		it { should cmp user }
	end

end

control 'Give the Apache User Account an Invalid Shell' do
	impact 1.0
	title '3.2 Give the Apache User Account an Invalid Shell'
	desc 'Service accounts such as the apache account represent a risk if they can be used to get a login
shell to the system.'
	etc_passwd_result = command('grep ' + user + ' /etc/passwd').stdout

	describe.one do
		describe etc_passwd_result do
			it { should include '/sbin/nologin' }
		end

		describe etc_passwd_result do
			it { should include '/dev/null' }
		end
	end
end

control 'Lock the Apache User Account' do
	impact 1.0
	title 'Lock the Apache User Account'
	desc "As a defense-in-depth measure the Apache user account should be locked to prevent logins, and
	to prevent a user from su'ing to apache using the password. In general, there shouldn't be a need
	for anyone to have to su as apache , and when there is a need, then sudo should be used instead,
	which would not require the apache account password."

	passw_status_result = command('passwd -S ' + user).stdout.split

	#remove user to remove potential L:s
	index_of_user = passw_status_result.index(user)
	passw_status_result.delete_at(index_of_user)
	passwd_status_result_string = passw_status_result.join(', ')
	describe passwd_status_result_string do
		it { should include 'L' }
	end
end


control'Verify Non-Existence of Directive or Existence of Correct Configuration' do
    impact 1.0
    title '3.8 Secure the Lock File (Scored)'
    desc 'If the lock file to be used as a mutex is placed in a writable directory, other accounts could create
	a denial of service attack and prevent the server from starting by creating a lock file with the
	same name.' 

	if apache_conf.params.has_key?('Mutex')

	    describe apache_conf.params.fetch('Mutex').inspect do
	    	it { should_not include 'fctl' }
	    	it { should_not include 'flock' }
	    	it { should_not include 'file' }
	    end

	    mutex_info = apache_conf.params.fetch('Mutex').inspect
		if mutex_info.include?('fctl') || mutex_info.include?('flock') || mutex_info.include?('file')
			path_to_mutex = apache_conf.params.fetch('Mutex').inspect.split(':')[1].split[0]
			
			if path_to_mutex.include?('${')
				#To make the envvars accessible in the terminal
				# command('source /etc/apache2/envvars')

				# path_to_mutex = command('echo ' + path_to_mutex).stdout
				#Obtaining the lock file path stated in the envvars file
				path_name=apache_conf.params.fetch('Mutex')[0].split('{')[1].split('}')[0]
				envvars_array = file(File.join(apache_conf.conf_dir, 'envvars')).content.split
				path_name_and_value = ''
				envvars_array.each do |element|
					if element.include?(path_name)
						path_name_and_value = element
					end
				end
				path_to_mutex = path_name_and_value.split('=')[1].split('$')[0]
			end

			doc_root = apache_conf.params.fetch('DocumentRoot')[0]

			describe file(path_to_mutex) do
          		its('path') { should_not include doc_root}
          		its ('owner') { should eq 'root' }
          		its ('group') { should eq 'root'}
          		it { should_not be_writable.by('group') }
    			it { should_not be_writable.by('others') }
        	end

        	describe command('mount').stdout do
        		it { should_not include path_to_mutex }
        	end
        end
    end
end

control 'Secure the PID file' do
	impact 1.0
	title '3.9 Secure the Pid File'
	desc 'If the PidFile is placed in a writable directory, other accounts could create a denial of service
	attack and prevent the server from starting by creating a pid file with the same name.'
end

control 'Remove Default Content' do
	impact 1.0
	title 'Remove Default HTML Content (Scored)'
	desc 'Historically these sample content and features have been remotely exploited and can provide
	different levels of access to the server. In the Microsoft arena, Code Red exploited a problem
	with the index service provided by the Internet Information Service. Usually these routines are
	not written for production use and consequently little thought was given to security in their
	development.'

	

	doc_root = apache_conf.params.fetch('DocumentRoot')[0]
	describe command('ls ' + doc_root).stdout do
		it { should_not include 'index.html' }
	end

	describe command('ls /usr/share/doc/ | grep apache2').stdout do
		it { should_not include 'apache2-doc' }
	end
	

	# if apache_conf.params.include?('<Location')
	#  	keys_array = apache_conf.params.keys
	# 	index_array = []
	# 	keys_array.each do |key|
	# 		if key.include?("<Location")
	# 			index_array.push(keys_array.index(key))
	# 		end
	# 	end
	# 	index_array.each do |index|

	# 		describe index do
	# 			it { should cmp< 100 }
	# 		end
	# 	end
	# end 
	describe apache_conf.content do
		it { should_not include '<Location /server-status>' }
		it { should_not include '<Location /server-info>'  }
		it { should_not include '<Location /perl-status>' }
	end 
end

control 'Remove Default CGI Content' do
	impact 1.0
	title '5.5 Remove Default CGI Content printenv'
	desc 'CGI programs have a long history of security bugs and problems associated with improperly
	accepting user-input. Since these programs are often targets of attackers, we need to make sure
	that there are no unnecessary CGI programs that could potentially be used for malicious
	purposes. Usually these programs are not written for production use and consequently little
	thought was given to security in their development. The printenv script in particular will
	disclose inappropriate information about the web server including directory paths and detailed
	version and configuration information.'
	conf_array = apache_conf.content.split
	cgi_path_array =[]
	conf_array.each do | element |
		if element.eql? 'ScriptAlias' || element.eql? 'Script' 
			index_of_element = conf_array.index(element)

			#the directives have the syntax Directive [URL-path] file-path|directory-path
			#if the URL Path includes cgi/bin
			#then obation the file/directory-path
			if conf_array[index_of_element + 1].include?('cgi-bin')
				cgi_path_array.push(conf_array[index_of_element+ 2])
			end
		end
	end

	cgi_path_array.each do |path|
		describe command('ls ' + path).stdout do
			it { should_not include 'printenv' }
		end
	end
end

# control 'Verify Directive Exists on Server Level and Verify Its Value'
# impact 1.0
# title '5.12 Deny IP Address Based Requests' 
# desc "A common malware propagation and automated network scanning technique is to use IP
# addresses rather than host names for web requests, since it's much simpler to automate. By
# denying IP based web requests, these automated techniques will be denied access to the website.
# Of course, malicious web scanning techniques continue to evolve, and many are now using
# hostnames, however denying access to the IP based requests is still a worthwhile defense."

# conf_hash = apache_conf.params
# describe conf_hash do
# 	it { should include 'RewriteCond' }
# end

# 	if conf_hash.include?('RewriteCond')
# 		describe conf_hash.fetch('RewriteCond').inspect do
# 			it { should cmp "%{HTTP_HOST} !^" + host_name + "[NC]", "%{REQUEST_URI} !^/error [NC]"}



