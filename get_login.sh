#!/bin/bash
input_file=$1

# Get the first element of a space delimited string
firstEleString() {
	IFS=" " read -ra arr <<< "$1"
	return "${arr[0]}"
}

# Get every time "login" string is seen. Default text for Telnet login
login_locs=`tshark -Y 'telnet.data contains "login"' -T fields -e "frame.number" -r $input_file`

password_data=`tshark -Y 'telnet.data contains "Password"' -T fields -e "frame.number" -e "ip.src" -e "ip.dst" -r $input_file`

# Get first time "login" is seen
firstEleString $login_locs
username_location=$?

# Parse the password_data section for password frame number, ip source, and ip destination
i=0
for variable in $password_data
do
	case $i in
		0)
			password_frame_no=$variable
			;;
		1)
			server_ip=$variable
			;;
		2)
			client_ip=$variable
			;;
	esac
	((i++))
done

# Get location of newline character that signifies where the password ends
pwd_end_loc_whitespace=`tshark -Y 'telnet.data contains 0d:0a and frame.number > '$password_frame_no -T fields -e "frame.number" -r $input_file`

firstEleString $pwd_end_loc_whitespace
password_end_loc=$?

# The destination and source swap because the server was emitting the $password_data, so now we reverse server_ip and client_ip to find the client emitted data

# Get all packets that are more than 
username=`tshark -Y 'frame.number < '$password_frame_no' and frame.number > '$username_location' and ip.src == '$client_ip' and ip.dst == '$server_ip -T fields -e "telnet.data" -r $input_file | tr -d '\n' | tr -d '\r'`

password=`tshark -Y 'frame.number > '$password_frame_no' and frame.number < '$password_end_loc' and ip.src == '$client_ip' and ip.dst == '$server_ip -T fields -e "telnet.data" -r ./telnet.pcap | tr -d '\n' | tr -d '\r'`

if [[ -z $username ]] && [[ -z $password ]]; then
	echo "Could not find telnet credenials"
else
	echo -e "Found! \nUsername: $username \nPassword: $password"
fi


