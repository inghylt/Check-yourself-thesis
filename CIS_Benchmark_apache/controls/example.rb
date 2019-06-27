# encoding: utf-8
# copyright: 2018, The Authors

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
	
end
