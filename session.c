//variables for session maintnance
int * free_sessions = NULL;
static int session_index = 0;
static int free_session_index = 0;
Session ** session_array = NULL;
Session ** temps_array;

//variables for connection maintenance
int * free_connections = NULL;
static int connection_index = 0;
static int free_connection_index = 0;
Connection ** connection_array = NULL;
Connection ** tempc_array;

//free ip list
struct free_ip {
	uint32_t ip;
	struct free_ip * next;
};

struct free_ip * fr_ip = NULL;

//create a session entry in the session array
int create_session(struct ether_addr client_l2addr) {

	int result = -1;

	if (free_sessions != NULL) {
		int index = get_sslot();
		update_session(index, client_l2addr);
		result = index;
	} else {
		if (session_array == NULL) {
			session_array = (Session **) malloc(sizeof(Session *));
			if (session_array != NULL) {
				session_array[session_index] = (Session *) malloc(sizeof(Session));
				if (session_array[session_index] != NULL) {
					if (fill_session(session_index, client_l2addr)) {
						result = session_index;
						session_index++;
					}
				}
			}
		} else {
			temps_array = (Session **) realloc(session_array, (session_index+1) * sizeof(Session *));
			if (temps_array != NULL) {
				session_array = temps_array;
				session_array[session_index] = (Session *) malloc(sizeof(Session));
				if (session_array[session_index] != NULL) {
					if (fill_session(session_index, client_l2addr)) {
						result = session_index;
						session_index++;
					}
				}
			}
		}
	}

	return result;
}


//get a free slot if available
int get_sslot() {

	int index = free_sessions[free_session_index-1];
	free_sessions = (int *) realloc(free_sessions, (free_session_index-1) * sizeof(int));
	free_session_index--;
	if (free_session_index == 0) {
		free_sessions = NULL;
	}
	return index;
}


//fill a session given session index and mac
int fill_session(int index, struct ether_addr client_l2addr) {

	uint32_t ip;
	if ((ip=check_and_set_ip()) == 0) {
		return 0;
	}
	(session_array[index])->state = STATE_SESS_CRTD;
	(session_array[index])->client_mac_addr = client_l2addr;
	(session_array[index])->client_ipv4_addr = ip;
	(session_array[index])->session_id = index+1;
	(session_array[index])->index = NULL;
	(session_array[index])->auth_ident = 0;
	(session_array[index])->echo_ident = 0;
	(session_array[index])->ip_ident = 0;
	(session_array[index])->mru = 1492; //keeping 1492 as the default
	return 1;
}


//check if an ip already exist in ip free list, else create one
uint32_t check_and_set_ip() {
	uint32_t ip;
	if (fr_ip != NULL) {
		ip = fr_ip->ip;
		if (fr_ip->next == NULL) {
			free(fr_ip);
			fr_ip = NULL;
		} else {
			struct free_ip * ipkeep = fr_ip;
			fr_ip = fr_ip->next;
			free(ipkeep);
		}
	} else {
		ip = get_ip();
	}
	return ip;
}


//update a session (keep the ip from last assignment)
void update_session(int index, struct ether_addr client_l2addr) {

	(session_array[index])->state = STATE_SESS_CRTD;
	(session_array[index])->client_mac_addr = client_l2addr;
	(session_array[index])->session_id = index+1;
	(session_array[index])->index = NULL;
	(session_array[index])->auth_ident = 0;
	(session_array[index])->echo_ident = 0;
	(session_array[index])->ip_ident = 0;
	(session_array[index])->mru = 1492; //keeping 1492 as the default
}


//delete a session
void delete_session(int index) {

	if (index == (session_index-1)) {
		//keep ip in fr_ip list
		struct free_ip * ipkeep = fr_ip;
		if (ipkeep == NULL) {
			fr_ip = (struct free_ip *) malloc(sizeof(struct free_ip));
			fr_ip->ip = (session_array[index])->client_ipv4_addr;
			fr_ip->next = NULL;
		} else {
			while (ipkeep->next != NULL) {
				ipkeep = ipkeep->next;
			}
			ipkeep->next = (struct free_ip *) malloc(sizeof(struct free_ip));
			ipkeep = ipkeep->next;
			ipkeep->ip = (session_array[index])->client_ipv4_addr;
			ipkeep->next = NULL;
		}
		//free the session
		free(session_array[index]);
		session_array = (Session **) realloc(session_array, (session_index-1) * sizeof(Session *));
		session_index--;
		if (session_index == 0) {
			session_array = NULL;
		}
	} else {
		//we don't actually free the space but keep it in free_sessions array
		if (free_sessions == NULL) {
			free_sessions = (int *) malloc(sizeof(int));
			free_sessions[free_session_index] = index;
			free_session_index++;
		} else {
			free_sessions = (int *) realloc(free_sessions, (free_session_index+1) * sizeof(int));
			free_sessions[free_session_index] = index;
			free_session_index++;
		}

		//release all connection indexes
		Session * session = session_array[index];
		struct conn_index * con_index = session->index;
		while (con_index != NULL) {
			while (con_index->next != NULL) {
				if ((con_index->next)->next != NULL) {
					con_index = con_index->next;
				} else {
					free(con_index->next);
					con_index->next = NULL;
				}
			}

			if (session->index != NULL && (session->index)->next == NULL) {
				free(session->index);
				session->index = NULL;
			}
			con_index = session->index;
		}
	}
}


//create a connection entry in the connection array
int create_connection(uint16_t session_index, uint16_t port) {

	int result = -1;

	if (free_connections != NULL) {
		int index = get_cslot();
		fill_connection(index, session_index, port);
		result = index;
	} else {
		if (connection_array == NULL) {
			connection_array = (Connection **) malloc(sizeof(Connection *));
			if (connection_array != NULL) {
				connection_array[connection_index] = (Connection *) malloc(sizeof(Connection));
				if (connection_array[connection_index] != NULL) {
					if (fill_connection(connection_index, session_index, port)) {
						result = connection_index;
						connection_index++;
					}
				}
			}
		} else {
			tempc_array = (Connection **) realloc(connection_array, (connection_index+1) * sizeof(Connection *));
			if (tempc_array != NULL) {
				connection_array = tempc_array;
				connection_array[connection_index] = (Connection *) malloc(sizeof(Connection));
				if (connection_array[connection_index] != NULL) {
					if (fill_connection(connection_index, session_index, port)) {
						result = connection_index;
						connection_index++;
					}
				}
			}
		}
	}

	//if a valid index created, add it into the session
	if (result >= 0) {

		Session * session = session_array[session_index];
		struct conn_index * con_index = session->index;

		if (con_index == NULL) {
			session->index = (struct conn_index *) malloc(sizeof(struct conn_index));
			con_index = session->index;
		} else {
			//parse till the end
			while (con_index != NULL) {
				if (con_index->next == NULL) {
					break;
				}
				con_index = con_index->next;
			}
			con_index->next = (struct conn_index *) malloc(sizeof(struct conn_index));
			con_index = con_index->next;
		}
		con_index->index = result;
		con_index->next = NULL;
	}

	return result;
}


//get a free slot if available
int get_cslot() {

	int index = free_connections[free_connection_index-1];
	free_connections = (int *) realloc(free_connections, (free_connection_index-1) * sizeof(int));
	free_connection_index--;
	if (free_connection_index == 0) {
		free_connections = NULL;
	}
	return index;
}

//provide the connection structure corresponding to given port from internet
Connection * get_client_connection(uint16_t port) {
	uint16_t index = port-10000;
	if (index >= 0 && index < connection_index) {
		return connection_array[index];
	}
	return NULL;
}


//fill connection at a given index
int fill_connection(int c_index, uint16_t s_index, uint16_t port) {

	(connection_array[c_index])->session_index = s_index;
	(connection_array[c_index])->port_origl = port;
	(connection_array[c_index])->port_assnd = c_index+10000; //NAT port starting at 10000
}


//delete a connection
void delete_connection(int index) {

	Session * session = session_array[(connection_array[index])->session_index];

	if (index == (connection_index-1)) {
		free(connection_array[index]);
		connection_array = (Connection **) realloc(connection_array, (connection_index-1) * sizeof(Connection *));
		connection_index--;
		if (connection_index == 0) {
			connection_array = NULL;
		}
	} else {
		//we don't actually free the space but keep it in free_connections array
		if (free_connections == NULL) {
			free_connections = (int *) malloc(sizeof(int));
			free_connections[free_connection_index] = index;
			free_connection_index++;
		} else {
			free_connections = (int *) realloc(free_connections, (free_connection_index+1) * sizeof(int));
			free_connections[free_connection_index] = index;
			free_connection_index++;
		}
	}

	//remove a connection index from session
	struct conn_index * con_index = session->index;
	struct conn_index * con_pre = NULL;
	int found = 0;
	while (con_index != NULL) {
		if (con_index->index == index) {
			found = 1;
			break;
		}
		con_pre = con_index;
		con_index = con_index->next;
	}

	if (session->index != NULL && con_index == session->index && found) {
		session->index = con_index->next;
		free(con_index);
	} else if (session->index != NULL && found) {
		con_pre->next = con_index->next;
		free(con_index);
	}
}


//check if a connection already exists, else create one
int check_and_set_connection(int s_index, uint16_t port) {

	int found = 0;
	int c_index = -1;
	Session * session = session_array[s_index];
	struct conn_index * con_index = session->index;

	//check if index already exists in session
	while (con_index != NULL) {
		if ((connection_array[con_index->index])->port_origl == port) {
			found = 1;
			c_index = con_index->index;
			break;
		}
		con_index = con_index->next;
	}

	//index not found, create one
	if (!found) {
		c_index = create_connection((uint16_t)s_index, port);
	}

	return c_index;
}
