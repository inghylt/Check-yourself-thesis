# encoding: utf-8
# copyright: 2018, The Authors

params = yaml(content: inspec.profile.file('params.yml')).params
forbidden_modules = params['forbidden-modules']
host_name = params['host-name']

#Example of how the controls can be adapted to suit a variety of operating systems
if os.debian?
  loaded_modules_command = 'apache2ctl -M'
  apache_name = 'apache2'
  package_info_command = 'apt show apache2'
  index_distance = 1
  version_string = 'Version:'
  version_string2 = 'version:'
  log_file_location = '/etc/logrotate.d/apache2'
  default_page_content = 'Default Page: It works'
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



control 'Verify That Module Is Enabled' do 
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

control 'Verify That Module Is Disabled' do
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
      forbidden_modules.each do |forbidden_module|           
      	it{ should_not include forbidden_module }
    	end
	end
end

control 'Verify That Apache Web Server Run as a Non-Root User' do
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

control 'Verify That the Apache User Account Has an Invalid Shell' do
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

control 'Verify That the Apache User Account Is Locked' do
	impact 1.0
	title '3.3 Lock the Apache User Account'
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

control 'Verify Correct Ownership' do
	impact 1.0
	title '3.4 Set Ownership on Apache Directories and Files'
	desc 'Restricting ownership of the Apache files and directories will reduce the probability of
	unauthorized modifications to those resources.'
	apache_files_and_dir = command('find /etc/apache2 -print').stdout.split
	  	apache_files_and_dir.each do |file|
	    	describe file(file) do
	    		its('owner') {should eq 'root'}
	      end
	    end
 end

control 'Verify Correct Permissions' do
	impact 1.0
	title '3.6 Restrict Other Write Access on Apache Directories and Files'
	desc 'None of the Apache files and directories, including the Web document root must allow other
	write access. Other write access is likely to be very useful for unauthorized modification of web
	content, configuration files or software for malicious attacks.'
	apache_files_and_dir = command('find /etc/apache2 -print').stdout.split
	  	apache_files_and_dir.each do |file|
	    	describe file(file) do
	    		it { should_not be_writable.by('others') }
	      	end
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
				
				#Obtaining the lock file path stated in the envvars file
				path_name=apache_conf.params.fetch('Mutex')[0].split('{')[1].split('}')[0]
				envvars_array = file(File.join(apache_conf.conf_dir, 'envvars')).content.split
				path_name_and_value = ''
				envvars_array.each do |element|
					if element.include?(path_name)
						path_name_and_value = element
					end
				end
				#Ignoring $SUFFIX as there is no way found to access this
				path_to_mutex = path_name_and_value.split('=')[1].split('$')[0]
			end

			doc_roots = apache_conf.params.fetch('DocumentRoot')
			doc_roots.each do |docroot|
				describe file(path_to_mutex) do
		      		its('path') { should_not include docroot}
		      		its ('owner') { should eq 'root' }
		      		its ('group') { should eq 'root'}
		      		it { should_not be_writable.by('group') }
					it { should_not be_writable.by('others') }
		    	end
		    end

	    	describe command('mount').stdout do
	    		it { should_not include path_to_mutex }
	    	end
	    end
	end
end


control 'Verify That the Apache Process ID (PID) File Is Secured' do
	impact 1.0
	title '3.9 Secure the Pid File'
	desc 'If the PidFile is placed in a writable directory, other accounts could create a denial of service
	attack and prevent the server from starting by creating a pid file with the same name.'
	describe apache_conf.params do
		it { should include 'PidFile' }
	end

	if apache_conf.params.include?('PidFile')
		pid_path = apache_conf.params.fetch('PidFile')[0]
		if pid_path.include?('${')
			path_name=apache_conf.params.fetch('PidFile')[0].split('{')[1].split('}')[0]
				envvars_array = file(File.join(apache_conf.conf_dir, 'envvars')).content.split
				path_name_and_value = ''
				envvars_array.each do |element|
					if element.include?(path_name)
						path_name_and_value = element
					end
				end
				#Ignoring $SUFFIX as there is no way found to access this
				pid_path_temp = path_name_and_value.split('=')[1].split('$')
				pid_path_ending = ''
					if pid_path_temp[1].include?('SUFFIX/')
						pid_path_ending = pid_path_temp[1].split('/')[1]
					end
				pid_file = file(File.join(pid_path_temp[0], pid_path_ending))
		end

		doc_roots = apache_conf.params.fetch('DocumentRoot')
		doc_roots.each do |docroot|
			describe pid_file do
	      		its('path') { should_not include docroot}
	      		its ('owner') { should eq 'root' }
	      		its ('group') { should eq 'root'}
	      		it { should_not be_writable.by('group') }
				it { should_not be_writable.by('others') }
	    	end
	    end
    end
end

control 'Find Directive, Verify Existance or Non-Existance of Nested Directive and Its Value & Verify Non-Existance of Directive or Text' do
    impact 1.0
    title '4.3 Restrict Override for the OS Root Directory'
    desc "While the functionality of htaccess files is sometimes convenient, usage decentralizes the
	access controls and increases the risk of configurations being changed or viewed inappropriately
	by an unintended or rogue .htaccess file. Consider also that some of the more common
	vulnerabilities in web servers and web applications allow the web files to be viewed or to be
	modified, then it is wise to keep the configuration out of the web server from being placed in
	.htaccess files."
    describe apache_conf.content do
    	it { should include "<Directory />" }
    end

    if apache_conf.content.include?("<Directory />")

    	splitted_content = apache_conf.content.split
    	index_dir_content_beginning = 0
    	splitted_content.each_cons(2) do |first, second|
    		if first =='<Directory' && second=='/>'
    			index_dir_content_beginning = splitted_content.index(second)
    		end
    	end

    	#Obtaining the content inside the root directory
    	index_dir_content_end = index_dir_content_beginning
    	while index_dir_content_end < splitted_content.size 
    		if splitted_content[index_dir_content_end] == '</Directory>'
    			break
    		else
    			index_dir_content_end +=1
    		end
    	end

    	counter = index_dir_content_beginning
    	dir_content = []
    	while counter < index_dir_content_end 
    		dir_content.push(splitted_content[counter])
    		counter +=1
    	end

    	describe dir_content.inspect do
    		it { should_not include 'AllowOverrideList' }
    		it { should include "AllowOverride" }
    	end

    	index_of_AllowOverride = dir_content.index('AllowOverride')
    	describe dir_content[index_of_AllowOverride +1] do
    		it { should cmp "None" }
    	end
    end
end

control 'Verify Value of Directive' do
	impact 1.0
    title "8.2 Set ServerSignature to 'Off'"
    desc "Server signatures are helpful when the server is acting as a proxy, since it helps the user
distinguish errors from the proxy rather than the destination server, however in this context there
is no need for the additional information and we want to limit leakage of unnecessary
information."

	describe apache_conf.content do 
		it { should include 'ServerSignature Off' }
	end

end

control 'Verify That Default Content Is Removed' do
	impact 1.0
	title '5.4 Remove Default HTML Content'
	desc 'Historically these sample content and features have been remotely exploited and can provide
	different levels of access to the server. In the Microsoft arena, Code Red exploited a problem
	with the index service provided by the Internet Information Service. Usually these routines are
	not written for production use and consequently little thought was given to security in their
	development.'

	

	doc_roots = apache_conf.params.fetch('DocumentRoot')
	doc_roots.each do |docroot|
		describe command("grep -R '" + default_page_content + "' " + docroot).stdout do
			it { should_not include 'Default Page: It works' }
		end
	end


	describe command('ls /usr/share/doc/ | grep apache2').stdout do
		it { should_not include 'apache2-doc' }
	end
	
	describe apache_conf.content do
		it { should_not include '<Location /server-status>' }
		it { should_not include '<Location /server-info>'  }
		it { should_not include '<Location /perl-status>' }
	end 
end

control 'Verify That Default CGI Content Is Removed' do
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
		if element == 'ScriptAlias' || element == 'Script' || element == 'ScriptAliasMatch'
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

control 'Verify Directive Exists on Server Level and Verify Its Value' do
	impact 1.0
	title '5.12 Deny IP Address Based Requests' 
	desc "A common malware propagation and automated network scanning technique is to use IP
	addresses rather than host names for web requests, since it's much simpler to automate. By
	denying IP based web requests, these automated techniques will be denied access to the website.
	Of course, malicious web scanning techniques continue to evolve, and many are now using
	hostnames, however denying access to the IP based requests is still a worthwhile defense."

	conf_hash = apache_conf.params
	describe conf_hash do
		it { should include 'RewriteCond' }
		it { should include 'RewriteRule' }
	end

	if conf_hash.include?('RewriteCond')
		describe conf_hash.fetch('RewriteCond').inspect do
			it { should include "%{HTTP_HOST} !^" + host_name + " [NC]" }
			it { should include "%{REQUEST_URI} !^/error [NC]" }
		end
	end

	if conf_hash.include?('RewriteRule') 
		describe conf_hash.fetch('RewriteRule') do
			it { should cmp "^.(.*) - [L,F]" }
		end
	end


end

control 'Verify Correct Setting of Log Storage and Rotation' do
	impact 1.0
    title '6.4 Log Storage and Rotation'
    desc "Keep in mind that the generation of logs is under a potential attacker's control. So, do not hold
any Apache log files on the root partition of the OS. This could result in a denial of service
against your web server host by filling up the root partition and causing the system to crash. For
this reason, it is recommended that the log files should be stored on a dedicated partition.
Likewise consider that attackers sometimes put information into your logs which is intended to
attack your log collection or log analysis processing software. So, it is important that they are not
vulnerable. Investigation of incidents often require access to several months or more of logs,
which is why it is important to keep at least 3 months available. Two common log rotation
utilities include rotatelogs(8) which is bundled with Apache, and logrotate(8) commonly
bundled on Linux distributions are described in the remediation section."

	
	describe file(log_file_location) do 
		its ('content') { should include 'missingok' }
		its ('content') { should include 'notifempty' }
		its ('content') { should include 'sharedscripts' }
		its ('content') { should include 'postrotate' }
		its ('content') { should include 'weekly' }
		its ('content') { should include 'rotate 13' }
	end

end

control 'Verify That Applicable Patches Are Applied' do
    impact 1.0
    title '6.5 Apply Applicable Patches'
    desc "Obviously knowing about newly discovered vulnerabilities is only part of the solution; there
	needs to be a process in place where patches are tested and installed. These patches fix diverse
	problems, including security issues. It is recommended to use the Apache packages and updates
	provided by the Linux platform vendor rather than building from source when possible, in order
	to minimize the disruption and the work of keeping the software up-to-date."

		#Obtain most resent version number
        result_array = command(package_info_command).stdout.split
        index_of_version_string = result_array.find_index(version_string).to_i
        index_of_version_number = index_of_version_string + index_distance
        version = result_array[index_of_version_number]
        version_number = version.split('-')[0]

        #Obtain current version number
        recent_version_array = command('apache2 -v').stdout.split
        index_of_version_string = recent_version_array.index(version_string2).to_i
        recent_version = recent_version_array[index_of_version_string + index_distance]
        recent_version_number = recent_version.split('/')[1]

        describe recent_version_number do
          it { should include version_number }
        end
      
end


control 'Verify That a Valid Trusted Certificate Is Installed' do
    impact 1.0
    title '7.2 Install a Valid Trusted Certificate'
    desc "A digital certificate on your server automatically communicates your site's authenticity to
	visitors' web browsers. If a trusted authority signs your certificate, it confirms for the visitor they
	are actually communicating with you, and not with a fraudulent site stealing credit card numbers
	or personal information."
    conf_array = apache_conf.content.split
    describe conf_array do
    	it { should include 'SSLCertificateFile' }
    	it { should include 'SSLCertificateKeyFile' }
    	it { should include 'SSLCACertificateFile' }
    end

    if conf_array.include?('SSLCertificateFile') && conf_array.include?('SSLCACertificateFile')
    	index_of_cert_file = conf_array.index('SSLCertificateFile')
    	cert_file_path = conf_array[index_of_cert_file +1 ]
    	index_of_ca_cert_file = conf_array.index('SSLCACertificateFile')
    	ca_cert_file_path =  conf_array[index_of_ca_cert_file +1]
    	
    	describe command('openssl verify -CAfile ' + ca_cert_file_path + ' -purpose sslserver ' + cert_file_path).stdout.split do
    		it { should_not include 'error' }
    		it { should_not include 'Error' }
    		it { should include 'OK' }
    	end 

    end


end


control 'Verify That a Default Hosted U2-0620 Application Web Page Is Displayed When a Requested Web Page Cannot Be Found' do
	impact 1.0
    title 'U2-0620'
    desc "The goal is to completely control the web user's experience in navigating any portion of the web document root directories. 
    Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end. 
    Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the Apache web server's directory structure 
    by locating directories without default pages. In the scenario, the Apache web server will display to the user a listing of the files in the directory being accessed. 
    By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version."

    docroot_path_array = apache_conf.params.fetch('DocumentRoot')
	docroot_path_array.each do |path|
		describe command('find ' + path + ' -type f -name index.html' ).stdout do
			it { should include 'index.html'}
		end
	end
end