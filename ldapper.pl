#!/usr/bin/perl
#
$version = "0.8";
#
# fixed ability to idenitfy BaseDN via RootDSE
#
# apt-get install libnet-ldap-perl
#
#
# -u argument is either user@domain.com
# or 'domain\user' 
# note the backslash is not escaped in 
# single quotes
#
# To Do
# Add ability to search password policy
# create 'report' format which runs all commands
# and outputs in more human readable format
#
# Add recursive grab of group info eg; user is 
# member of GroupX, grab GroupX description
# 
# Disabled accounts userAccountControl = 514
# http://support.microsoft.com/kb/305144
#
# objectClass = trustedDomain
# trustType = 2, trustDirection = 1
#

# Define the Base DN format is DC=pwn,DC=me
# $baseDN = "dc=site,dc=mycompany,dc=com";

use Term::ReadKey;
use Getopt::Std;
use POSIX();

use Net::DNS;

use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );

$groupFilter = "(objectClass=group)";
$siteFilter = "(objectClass=site)";
$subnetFilter = "(objectClass=subnet)";
$serverFilter = "(objectClass=computer)";
$siteServerFilter = "(objectClass=server)";
$userFilter = "(&(objectClass=user)(objectcategory=person))";
$trustFilter = "(objectClass=trustedDomain)";
$containerFilter = "(objectClass=Container)";
$ouFilter = "(objectClass=OrganizationalUnit)";

my %args;	

if ( @ARGV < 1 )
{
print " -= el Dapper Dan Usage =-\n";
print "-s Server (Target LDAP Server)\n";
print "-u User (user must be user\@domain or old style DOMAIN\\User)\n";
print "-d domain (used to create Base DN for ldap, eg site.company.com)\n";
print "\n -= Target Information =-\n";
print "-R (Run all Queries)\n";
print "   (currently: Computers, Groups, Users, Trusts, Sites)\n";
print "-C (list all computers in domain)\n";
print "-L (list all groups in domain (simple listing))\n";
print "-G (list all groups in domain and members of those groups)\n";
print "-S (list all Servers in domain)\n";
print "-U (list all Users in domain)\n";
print "-N (list all Subnets in domain)\n";
print "-T (list all Trusts in domain)\n";
print "-O (list of all Organizational Units - detailed)\n";
print "-g <group> (list all members of target group, case sensitive)\n";
print "-M <user> (list all groups <user> is a member of)\n";
print "-A <user> (list all attributes for <user> *NOTE* that this strips binary data)\n";
exit;
}

# Pretty Obvious
sub procWindowsTime{
   $timeInteger = @_[0];
   $retTime = POSIX::strftime( "%Y-%m-%d", localtime(($timeInteger/10000000)-11644473600) );
   return $retTime;
}


getopt('sugpdMA', \%args);

$server = $args{s};
$username = $args{u};
$groupname = $args{g};
$argDomain = $args{d};

$listAllGroups = $args{G};
$listGroupsSimple = $args{L};

$listAllServers = $args{S};
$listAllUsers = $args{U};
$listAllSubnets = $args{N};
$listAllTrusts = $args{T};
$generateReport = $args{R};
$listAllComputers = $args{C};
$userGroupMembers = $args{M};
$userAllAtributes = $args{A};

$listOrgUnits = $args{O};

if ($groupname) {
  $findGroup = "YES";
}

if ($generateReport)
{
 $listAllUsers = "YUP";
 $listAllGroups = "YUP";
 $listAllComputers = "YUP";
 $listAllSubnets = "YUP";
 $listOrgUnits = "YUP";
 $listAllTrusts = "YUP";
}

if ( $args{p} )
{
 $passwd = $args{p};
}
else
{
 print "Enter your password: ";
 ReadMode 'noecho';
 $passwd = ReadLine 0;
 chomp $passwd;
 ReadMode 'normal';
 print "\n";
}

if ( $argDomain )
{
  @domVals = split( '\.', $argDomain);
  $numElements=@domVals;
  $i = 1;

  foreach my $val (@domVals) {
    $baseDN .= "dc=".$val;
    if ($i < $numElements )
    {
	$baseDN .=",";
    }
    $i++;
   }
}

else {
    $obtainBaseDN = "YES";
}

printf("[+] Connecting to Server: $server\n");
printf("[+] User: $username\n");

if ( $baseDN ) 
{ 
 printf("[+] BaseDN: $baseDN\n");
}


if ( $obtainBaseDN)
{ 
	obtainBaseDN(); 
}

$page = Net::LDAP::Control::Paged->new(size => 999);



sub obtainBaseDN
{
 $ldap = Net::LDAP->new ( "$server" ) or die "$@";
 $mesg = $ldap->bind ( "$username", password => $passwd, version => 3 );          
 $mesg->code( ) && die $mesg->error;

 my $page = Net::LDAP::Control::Paged->new(size => 999);
 my $cookie;

 # to try and obtain baseDN we will perform an nslookup of the target
 # IP address and use the domain we receive, note that we are querying
 # the target IP itself, as we are assuming it also runs DNS
 print "[+] BaseDN not specified, querying RootDSE\n";
 my $dse = $ldap->root_dse( attrs => ['defaultNamingContext'] );
 my @contexts = $dse->get_value('namingContexts');
 
 $baseDN = $dse->get_value('defaultNamingContext');
  print "[+] Obtained baseDN: $baseDN\n";
}



# This loop will list all users within a domain
if ( $listAllUsers)
{
  while(1){
  $mesg = $ldap->search( base    => $baseDN, filter  => $userFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

  foreach $entry (@entries) {
   $cName = $entry->get_value("cn");
   $sName = $entry->get_value("sAMAccountName");
   $desc = $entry->get_value("description");
   $hDir = $entry->get_value("homeDirectory");
   $pwdLastSet = $entry->get_value("pwdLastSet");
   $lastLogon = $entry->get_value("lastLogon");

  $pwdLastSetTime = procWindowsTime($pwdLastSet);
  if( $lastLogon == 0 ) {
   $lastLogonTime = "Never"; }
  else {
   $lastLogonTime = procWindowsTime($lastLogon); }

   #Add whenCreated
   $lastTime = procWindowsTime($lastLogon);

    print "USER: $sName, $cName, DESC: $desc, HOME: $hDir, PWDRESET: $pwdLastSetTime, LASTLOGON: $lastLogonTime\n";
  }
 }
}

# this will list all computers in the domain
if ( $listAllComputers)
{
 while(1){
  $mesg = $ldap->search( base    => $baseDN, filter  => $serverFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

  foreach $entry (@entries) {
  $cName = $entry->get_value("cn");
  $dName = $entry->get_value("dnsHostName");
  $opSystem = $entry->get_value("operatingSystem");
  $osPack = $entry->get_value("operatingSystemServicePack");
  $lastLogon = $entry->get_value("lastLogonTimestamp");
  $lastTime = procWindowsTime($lastLogon);
  print "Computer: $cName, $dName, $opSystem $osPack, LastLogon: $lastTime\n";
  }
 }
}

# This loop will list all servers within domain
if ( $listAllServers)
{
 while(1){
  $mesg = $ldap->search( base => $baseDN, filter  => $serverFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;

   foreach $entry (@entries) {
   $cName = $entry->get_value("cn");
   $dName = $entry->get_value("dnsHostName");
   $opSystem = $entry->get_value("operatingSystem");
   $osPack = $entry->get_value("operatingSystemServicePack");
   $lastLogon = $entry->get_value("lastLogonTimestamp");
   $lastTime = procWindowsTime($lastLogon);
   
    if ( $opSystem =~ /erver/) 
    {
     print "Server: $cName, $dName, $opSystem $osPack, LastLogon: $lastTime\n";
    }
   }
 }
}



 # This loop will list all SUBNETS within domain
 if( $listAllSubnets )
 {
   $newBaseDN = "CN=Subnets,CN=Sites,CN=Configuration," . $baseDN;
   $mesg = $ldap->search( base    => $newBaseDN, filter => $subnetFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) {
   $cName = $entry->get_value("cn");
   $desc = $entry->get_value("description");
   $siteObject = $entry->get_value("siteObject");
   $location = $entry->get_value("location");
	 print "SUBNET: $cName, DESC: $desc, SITE: $siteObject, LOCATION: $location\n";
   }
 }


# This loop will list all Members of the group
# specified by the -g command line argument
 if ( $findGroup )
 {
   printf("[+] Looking for all users in group $groupname\n");

   $mesg = $ldap->search( base    => $baseDN, filter  => $groupFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) 
   {
   	$gname = $entry->get_value("cn");
   	if ($groupname && $gname eq $groupname)
   	{
    	print "[I] Found group $gname on server\n";
    	$description = $entry->get_value("description");
    	print "[I] Group Description: $description\n";
    	@members = $entry->get_value( "member");
    	foreach $member (@members)
    	{
     		#print "Running with filter $member\n";
     		$userfilter = "(objectClass=user)";
     		$newmesg = $ldap->search( base => $member, filter=> $userfilter);
     		@nentries = $newmesg->entries;
     		foreach $nentry (@nentries) {
       			$sam = $nentry->get_value("sAMAccountName");
       			print "$groupname: $sam\n";
     		}
    	}
    }
   }
 }








 # This loop will list all Trusts within domain
 if( $listAllTrusts )
 {
   print "[+] Listing all Trusts\n";

   #$newBaseDN = "CN=Trusted-Domain,CN=SCHEMA,CN=Configuration," . $baseDN;
   $newBaseDN = $baseDN;

   $mesg = $ldap->search( base    => $newBaseDN, filter => $trustFilter,  control => [$page] );
   $mesg->code && die "[-]Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) 
   {
 	#trustType, trustDirection, trustPartner
   $flatName = $entry->get_value("flatName");
   $Name = $entry->get_value("name");
   $cName = $entry->get_value("cn");
   $trustPartner = $entry->get_value("trustPartner");
   $trustType = $entry->get_value("trustType");
   $trustDirection = $entry->get_value("trustDirection");

   #trustType (1=WindowsNT, 2=ActiveDirectory 2003 or newer, 3=Kerberos Realm, 4=DCE);
   #trustDirection (1=Inbound, 2=Outbound, 3=BiDirectional);
   #define arrays based on previous definitions

   @tType = ( "NA", "WindowsNT" ,"ActiveDirectory 2K3+" ,"KerberosRealm","DCE");
   @tDirection = ( "NA","Inbound","Outbound","Bidirectional");

   $trustType .= " @tType[$trustType]";
   $trustDirection .= " @tDirection[$trustDirection]";

   print "Trust: $flatName: $cName, Partner: $trustPartner, Type: $trustType, Direction: $trustDirection\n";

   #Now perform dns lookup of domain controllers for
   #target domain specified as trustedDomain
   #Note the second DNS query to obtain the IP address of the SRV record
    my $res   = Net::DNS::Resolver->new(nameservers => [$server, $server]);
    my $query=$res->search("_ldap._tcp.$trustPartner", SRV);

    if ($query) {
        @answers=$query->answer;
		foreach my $rr ($query->answer) 
		{
	  		$hostRes = Net::DNS::Resolver->new;
	  		$domainController = $rr->target;
	  		$hostReply = $hostRes->search( $domainController );
	  		if ($hostReply)
	  		{
	  			foreach my $rr ($hostReply->answer) 
	  			{
            	 next unless $rr->type eq "A";
	    		 $hostAddy = $rr->address;
	  			}
	  		}
	  	print "\t$flatName Domain Controller: " . $rr->target . " ($hostAddy)\n";
		}
	} 
   }
}

# This loop will list all Organizational Units
if ( $listOrgUnits)
{
 while (1){
  $mesg = $ldap->search( base => $baseDN, filter => $ouFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

 	foreach $entry (@entries) 
 	{
  	 $name = $entry->get_value("name");
  	 $cName = $entry->get_value("cn");
  	 $desc = $entry->get_value("description");
   	 $managedBy = $entry->get_value("managedBy");
     $dn = $entry->get_value("distinguishedName");
     print "OU: $name, DESC: $desc, Manager: $managedBy, DN: $dn \n";
 	}
}
 if (defined($cookie) && length($cookie)) {
    print "abnormal exit\n";
    # Abnormal exit, so let the server know we do not want any more
    $page->cookie($cookie);
    $page->size(0);
    $ldap->search(control => [$page]);
 }
}



# This loop will list all groups within domain
if ( $listGroupsSimple )
{
 while(1){
  $mesg = $ldap->search( base    => $baseDN, filter  => $groupFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

  foreach $entry (@entries) {
    $gname = $entry->get_value("cn");
    $desc = $entry->get_value("description");
    print "Group: $gname: $desc\n";
  }
 }
}


 # This loop will list all groups within domain AND print out all members
if ( $listAllGroups )
{
 while(1)
 {
   $mesg = $ldap->search( base    => $baseDN, filter  => $groupFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

   foreach $entry (@entries) 
   {
      $gname = $entry->get_value("cn");
      $description = $entry->get_value("description");
      print "Group: $gname, Desc: $description\n";
      print "\tMembers: ";
      @members = $entry->get_value( "member");
      foreach $member (@members)
      {
         #print "Running with filter $member\n";
         $userfilter = "(objectClass=user)";
         $newmesg = $ldap->search( base => $member, filter=> $userfilter);
         @nentries = $newmesg->entries;
         foreach $nentry (@nentries) {
               $sam = $nentry->get_value("sAMAccountName");
               print "$sam,";
         }  
      }
     print "\n";
   }
  }
}

 # This loop will list all groups that user is a member of
 if ( $userGroupMembers )
 {
   print "[I] Checking $userGroupMembers group membership\n";
   $userMemberFilter = "(sAMAccountName=$userGroupMembers)";

   $mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) {
    @member = $entry->get_value("memberOf");
    foreach $member (@member)
    {
     print "Group: $member\n";
    }
   }
 }



 # This loop will list all attributes for the user
 if ( $userAllAtributes )
 {
   print "[I] Grabbing All Attributes for $userAllAtributes\n";
   $userMemberFilter = "(sAMAccountName=$userAllAtributes)";

   $mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

	my $entr;
 	foreach $entr ( @entries ) {
   		print "DN: ", $entr->dn, "\n";

   	 my $attr;
     foreach $attr ( sort $entr->attributes ) {
     # skip binary we can't handle
     $theEntry = $entr->get_value ( $attr );
     $theEntry =~ s/[^[:print:]]+//g;
     $attr =~ s/[^[:print:]]+//g;
        print "  $attr : ", $theEntry ,"\n";
   	 }
    }
 }


# $testAttributes = "Yup";
# using this loop for testing of new queries
# it will list all attributes for the specified thing
 if ( $testAttributes )
 {
   print "[I] Grabbing All Attributes for $testAttribute\n";
   #$userMemberFilter = "(sAMAccountName=$userAllAtributes)";
   $mesg = $ldap->search( base => $baseDN, filter => $ouFilter, control => [$page] );
   #$mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

  my $entr;
  foreach $entr ( @entries ) {
      print "DN: ", $entr->dn, "\n";

     my $attr;
     foreach $attr ( sort $entr->attributes ) {
     # skip binary we can't handle
     $theEntry = $entr->get_value ( $attr );
     $theEntry =~ s/[^[:print:]]+//g;
     $attr =~ s/[^[:print:]]+//g;
        print "  $attr : ", $theEntry ,"\n";
     }
    print"#####################################################################\n\n\n";
   }
 }