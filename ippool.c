/* ippool - To provide ip and dns values to other part of the system.
 * Copyright (C) 2016  Sooraj Mandotti
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
 * sooraj.mandotti@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

unsigned int max_host = 0;
static unsigned int ip_count = 0;
uint8_t count_oct3 = 0;
uint8_t count_oct4 = 0;
int first_ip_assignment = 0;


/**
 * @brief This function returns ip and dns values.
 * @param session index.
 * @return structure filled PPPIpcpUsed.
 */
PPPIpcpUsed * get_ip_dns(int session_index)
{

    PPPIpcpUsed * ipDns;
    ipDns->ip = (session_array[session_index])->client_ipv4_addr;
    ipDns->dns1 = ip_dns1;
    ipDns->dns2 = ip_dns2;
    return ipDns;
}


/** 
 * @brief This function generates an ip from the ippool.
 * @return ip.
 */
uint32_t get_ip()
{

    uint32_t ip = 0;
    uint8_t oct1 = 0;
    uint8_t oct2 = 0;
    uint8_t oct3 = 0;
    uint8_t oct4 = 0;
    int error = 0;

    if(first_ip_assignment == 0 )
    {
        count_oct3 = start_ip_oct3;
        count_oct4 = start_ip_oct4;
        first_ip_assignment =1;
    }

    if(count_oct3 < end_ip_oct3 )
    {
        if(count_oct4 < 254)
        {
            oct3 = count_oct3;
            oct4 = count_oct4;
            count_oct4++;
        }
        else
        {
            count_oct4 =1 ;
            count_oct3++;
            oct3 = count_oct3;
            oct4 = count_oct4;
            count_oct4++;
        }


    }
    else if(count_oct3 == end_ip_oct3)
    {

        if(count_oct4 < end_ip_oct4)
        {
            oct3 = count_oct3;
            oct4 = count_oct4;
            count_oct4++;
        }
        else
        {
            error = 1 ;
        }
    }
    else
    {
        error = 1 ;
    }


    oct1 = start_ip_oct1;
    oct2 = start_ip_oct2;

    if (error)
    {
        oct1 = 0;
        oct2 = 0;
        oct3 = 0;
        oct4 = 0;
    }

    ip = oct1 | (oct2 << 8) | (oct3 << 16) | (oct4 << 24);

    return ip;
}


/**
 * @brief This function returns server's internet address.
 * @return server's internet address.
 */
uint32_t get_server_ip()
{

    uint32_t ip = ip_intra;
    return ip;
}
