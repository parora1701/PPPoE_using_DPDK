/* session - Session related declarations and functions.
 * Copyright (C) 2016  Puneet Arora
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
 * puneet.arora@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

//variables for session maintnance
int * free_sessions = NULL;
static int free_session_index = 0;
Session ** session_array = NULL;
Session ** temps_array;

//free ip list structure
struct free_ip
{
    uint32_t ip;
    struct free_ip * next;
};

struct free_ip * fr_ip = NULL;

/**
 * @brief Create a session entry in the session array.
 * @param ethernet address of client.
 * @return -1 if failed, greater than or equal 0 else.
 */
int create_session(struct ether_addr client_l2addr)
{

    int result = -1;
    pthread_mutex_lock(&conn_lock);

    //check if free sessions are available
    if (free_sessions != NULL)
    {
        int index = get_sslot();
        update_session(index, client_l2addr);
        result = index;
    }
    //create a session
    else
    {
        if (session_array == NULL)
        {
            session_array = (Session **) malloc(sizeof(Session *));
            if (session_array != NULL)
            {
                session_array[session_index] = (Session *) malloc(sizeof(Session));
                if (session_array[session_index] != NULL)
                {
                    if (fill_session(session_index, client_l2addr))
                    {
                        result = session_index;
                        session_index++;
                    }
                }
            }
        }
        else
        {
            temps_array = (Session **) realloc(session_array, (session_index+1) * sizeof(Session *));
            if (temps_array != NULL)
            {
                session_array = temps_array;
                session_array[session_index] = (Session *) malloc(sizeof(Session));
                if (session_array[session_index] != NULL)
                {
                    if (fill_session(session_index, client_l2addr))
                    {
                        result = session_index;
                        session_index++;
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&conn_lock);

    return result;
}


/**
 * @brief Get a free session slot.
 * @return slot.
 */
int get_sslot()
{

    int index = free_sessions[free_session_index-1];
    free_sessions = (int *) realloc(free_sessions, (free_session_index-1) * sizeof(int));
    free_session_index--;
    if (free_session_index == 0)
    {
        free_sessions = NULL;
    }
    return index;
}


/**
 * @brief Fill a session given session.
 * @param session index, ethernet address of client.
 * @return 0 if failed, 1 if success.
 */
int fill_session(int index, struct ether_addr client_l2addr)
{

    uint32_t ip;
    if ((ip=check_and_set_ip()) == 0)
    {
        return 0;
    }
    (session_array[index])->state = STATE_SESS_CRTD;
    (session_array[index])->client_mac_addr = client_l2addr;
    (session_array[index])->client_ipv4_addr = ip;
    (session_array[index])->session_id = index+1;
    (session_array[index])->host_uniq = NULL;
    (session_array[index])->hu_len = 0;
    (session_array[index])->auth_ident = 0;
    (session_array[index])->echo_ident = 0;
    (session_array[index])->ip_ident = 0;
    (session_array[index])->mru = 1492; //keeping 1492 as the default
    (session_array[index])->time = time(NULL);
    (session_array[index])->active = 1;
    return 1;
}


/**
 * @brief Checks if an ip already exist in ip free list, else create one.
 * @return ip.
 */
uint32_t check_and_set_ip()
{
    uint32_t ip;
    if (fr_ip != NULL)
    {
        ip = fr_ip->ip;
        if (fr_ip->next == NULL)
        {
            free(fr_ip);
            fr_ip = NULL;
        }
        else
        {
            struct free_ip * ipkeep = fr_ip;
            fr_ip = fr_ip->next;
            free(ipkeep);
        }
    }
    else
    {
        ip = get_ip();
    }
    return ip;
}


/**
 * @brief Update a session (keep the ip from last assignment).
 * @param session index, ethernet address of client.
 */
void update_session(int index, struct ether_addr client_l2addr)
{

    (session_array[index])->state = STATE_SESS_CRTD;
    (session_array[index])->client_mac_addr = client_l2addr;
    (session_array[index])->session_id = index+1;
    (session_array[index])->host_uniq = NULL;
    (session_array[index])->hu_len = 0;
    (session_array[index])->auth_ident = 0;
    (session_array[index])->echo_ident = 0;
    (session_array[index])->ip_ident = 0;
    (session_array[index])->mru = 1492; //keeping 1492 as the default
    (session_array[index])->time = time(NULL);
    (session_array[index])->active = 1;
}


/**
 * @brief Delete a session.
 * @param session index.
 */
void delete_session(int index)
{

    pthread_mutex_lock(&conn_lock);
    Session * session = session_array[index];

    //if at the end release the space
    if (index == (session_index-1))
    {
        //keep ip in fr_ip list
        struct free_ip * ipkeep = fr_ip;
        if (ipkeep == NULL)
        {
            fr_ip = (struct free_ip *) malloc(sizeof(struct free_ip));
            fr_ip->ip = (session_array[index])->client_ipv4_addr;
            fr_ip->next = NULL;
        }
        else
        {
            while (ipkeep->next != NULL)
            {
                ipkeep = ipkeep->next;
            }
            ipkeep->next = (struct free_ip *) malloc(sizeof(struct free_ip));
            ipkeep = ipkeep->next;
            ipkeep->ip = (session_array[index])->client_ipv4_addr;
            ipkeep->next = NULL;
        }
        //free host unique
        if (session_array[index]->host_uniq != NULL)
        {
            free(session_array[index]->host_uniq);
        }
        //free the session
        free(session_array[index]);
        session_array = (Session **) realloc(session_array, (session_index-1) * sizeof(Session *));
        session_index--;
        if (session_index == 0)
        {
            session_array = NULL;
        }
    }
    else
    {
        //we don't actually free the space but keep it in free_sessions array
        if (free_sessions == NULL)
        {
            free_sessions = (int *) malloc(sizeof(int));
            free_sessions[free_session_index] = index;
            free_session_index++;
        }
        else
        {
            free_sessions = (int *) realloc(free_sessions, (free_session_index+1) * sizeof(int));
            free_sessions[free_session_index] = index;
            free_session_index++;
        }

        //free host unique
        if (session_array[index]->host_uniq != NULL)
        {
            free(session_array[index]->host_uniq);
        }
        (session_array[index])->hu_len = 0;
        (session_array[index])->active = 0;
    }
    pthread_mutex_unlock(&conn_lock);
}


/**
 * @brief Session termination thread.
 */
void * check_and_free_session()
{

    while (1)
    {
        //check every 1 hr
        sleep(3600);

        int i;
        pthread_mutex_lock(&conn_lock);
        for (i = 0; i < session_index; i++)
        {
            time_t c_time = time(NULL);
            if (((session_array[i])->active == 1) && (fabs(c_time - ((session_array[i])->time)) >= (sess_timeout * 60)))
            {
                if (DEBUG)
                {
                    RTE_LOG(INFO, USER1, "=> Deleting a session\n");
                }
                send_term_req((uint16_t) i);
            }
        }
        pthread_mutex_unlock(&conn_lock);
    }
}

