/* pppoeconfig - Read config file and populate configuration related structure.
 * Copyright (C) 2016  Govind Singh
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * govind.singh@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STR_LEN 100
#define MAX_INT_LEN 6
#define DELIMITER "="

// this functions converts a given string containing a MAC address to
// an array of MAC address octets where each octet is stored at its corresponding index - 1
//Reference http://stackoverflow.com/questions/35227449/convert-ip-or-mac-address-from-string-to-byte-array-arduino-or-c
void convertStrToMac(const char* macStr, char separator, unsigned char* macByteArr, int maxBytes, int base)
{
    int i;
    for (i = 0; i < maxBytes; i++)
    {
        macByteArr[i] = strtoul(macStr, NULL, base);
        macStr = strchr(macStr, separator);
        if (macStr == NULL || *macStr == '\0')
        {
            break;
        }
        macStr++;
    }
}

// this functions converts a given string containing an IP address to
// an array of IP address octets where each octet is stored at its corresponding index - 1
// sep2 is used when the IP address string also contains subnet mask information
//Reference http://stackoverflow.com/questions/35227449/convert-ip-or-mac-address-from-string-to-byte-array-arduino-or-c
void convertStrToIP(const char* ipStr, char sep1, char sep2, unsigned char* ipByteArr, int maxBytes, int base)
{
    int i;
    for (i = 0; i < maxBytes; i++)
    {
        ipByteArr[i] = strtoul(ipStr, NULL, base);
        if ((sep2 != '\0') && (i == 3))
        {
            ipStr = strchr(ipStr, sep2);
        }
        else
        {
            ipStr = strchr(ipStr, sep1);
        }
        if (ipStr == NULL || *ipStr == '\0')
        {
            break;
        }
        ipStr++;
    }
}

// this function returns ConfigParameter structure containing
// all config params read from file pppoe.conf
// variable tracker always points to the current line being processed in config file
ConfigParameter * getConfigParameters()
{
    ConfigParameter *configParameter = (ConfigParameter *)malloc(sizeof(ConfigParameter));
    char *propName;
    char temp[MAX_INT_LEN];
    char macStr[MAX_STR_LEN];
    char ipStr[MAX_STR_LEN];

    int tracker = 1;
    const char filename[] = "./pppoe.conf";
    FILE *file = fopen ( filename, "r" );
    if ( file != NULL )
    {
        char file_lines[128];
        while ( fgets ( file_lines, sizeof file_lines, file ) != NULL )
        {
            propName = strtok(file_lines, DELIMITER);
            if(tracker == 2)
            {
                strcpy(configParameter->serviceName,strtok(NULL, "\n"));
            }
            else if(tracker == 4)
            {
                strcpy(configParameter->acName,strtok(NULL, "\n"));
            }
            else if(tracker == 6)
            {
                strcpy(temp,strtok(NULL, "\n"));
                configParameter->isDebug = (*temp) - '0';
            }
            else if(tracker == 8)
            {
                strcpy(temp,strtok(NULL, "\n"));
                configParameter->authProtocol = (*temp) - '0';
            }
            else if((tracker == 10) || (tracker == 12) || (tracker == 14))
            {
                strcpy(macStr,strtok(NULL, "\n"));
                if(tracker == 10)
                {
                    convertStrToMac(macStr, ':', configParameter->servToIntraMac, 6, 16);
                }
                else if(tracker == 12)
                {
                    convertStrToMac(macStr, ':', configParameter->servToInterMac, 6, 16);
                }
                else
                {
                    convertStrToMac(macStr, ':', configParameter->routerMac, 6, 16);
                }
            }
            else if((tracker == 16) || (tracker == 18) || (tracker == 20))
            {
                strcpy(ipStr,strtok(NULL, "\n"));
                if(tracker == 16)
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->servToIntraIP, 4, 10);
                }
                else if(tracker == 18)
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->servToInterIP, 4, 10);
                }
                else
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->routerIP, 4, 10);
                }
            }
            else if(tracker == 22)
            {
                strcpy(ipStr,strtok(NULL, "\n"));
                convertStrToIP(ipStr, '.', '/', configParameter->ipAddressPool, 5, 10);
            }
            else if((tracker == 24) || (tracker == 26))
            {
                strcpy(ipStr,strtok(NULL, "\n"));
                if(tracker == 24)
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->primaryDns, 4, 10);
                }
                else
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->secondaryDns, 4, 10);
                }
            }
            else if((tracker == 28) || (tracker == 30))
            {
                strcpy(temp,strtok(NULL, "\n"));
                if(tracker == 28)
                {
                    sscanf(temp, "%lf", &configParameter->sessionTimeout);
                }
                else
                {
                    sscanf(temp, "%lf", &configParameter->connectionTimeout);
                }
            }
            else if((tracker == 32) || (tracker == 34))
            {
                strcpy(ipStr,strtok(NULL, "\n"));
                if(tracker == 32)
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->routerIpStart, 4, 10);
                }
                else
                {
                    convertStrToIP(ipStr, '.', '\0', configParameter->routerIpEnd, 4, 10);
                }
            }
            tracker++;
        }
        fclose ( file );
    }
    else
    {
        printf("\n Unable to read file.");
    }
    return configParameter;
}


