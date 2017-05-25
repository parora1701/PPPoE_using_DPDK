/* pppoe_auth - authentication related declarations and functions.
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
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

//******Hashing with Linear Chaining Program, Hashing function used is Larsen's hashing algorithm for simple strings******//

#define TOTAL_ROW 500

// pre-C99 bool type does not exist, so defining our own
// Reference http://stackoverflow.com/questions/1921539/using-boolean-values-in-c
typedef enum { false = 0, true = !false } bool;

struct Hash *hashTable = NULL;

struct Node
{
    char password[20];
    struct Node *next;
};

struct Hash
{
    struct Node *head;
    int count;
};

// this function creates the Node to be inserted in Linked List
struct Node * createNode(char *password)
{
    struct Node *newnode;
    newnode = (struct Node *)malloc(sizeof(struct Node));
    strcpy(newnode->password, password);
    newnode->next = NULL;
    return newnode;
}

// a simple hash function
// using 64-bit int and prime number to provide better collision resolution
// reference http://stackoverflow.com/questions/98153/whats-the-best-hashing-algorithm-to-use-on-a-stl-string-when-using-hash-map
unsigned long long int hashFunction(const char* s)
{
    unsigned long long int hashVal = 0l;
    while (*s)
    {
        hashVal = hashVal * 31  +  *s++;
    }
    return hashVal;
}

// function to insert username & password that are read
// from passwd file, in hashtable
// Reference http://see-programming.blogspot.de/2013/05/chain-hashing-separate-chaining-with.html
void insertToHash(char *username, char *password)
{
    unsigned long long int hashVal = hashFunction(username);
    int hashIndex = hashVal % TOTAL_ROW;
    struct Node *newnode =  createNode(password);
    // head of list for the bucket with index = hashIndex
    if (!hashTable[hashIndex].head)
    {
        hashTable[hashIndex].head = newnode;
        hashTable[hashIndex].count = 1;
        return;
    }
    /* adding new Node to the list */
    newnode->next = (hashTable[hashIndex].head);
    /*
     * update the head of the list and no of
     * nodes in the current bucket
     */
    hashTable[hashIndex].head = newnode;
    hashTable[hashIndex].count++;
    return;
}

// this function deletes entry from hash table
// Reference http://see-programming.blogspot.de/2013/05/chain-hashing-separate-chaining-with.html
void deleteFromHash(char *username, char *password)
{
    int flag = 0;
    unsigned long long int hashVal = hashFunction(username);
    int hashIndex = hashVal % TOTAL_ROW;
    struct Node *temp, *myNode;
    /* get the list head from current bucket */
    myNode = hashTable[hashIndex].head;
    if (!myNode)
    {
        printf("Data is not available in hash Table\n");
        return;
    }
    temp = myNode;
    while (myNode != NULL)
    {
        if (strcasecmp(myNode->password,password) == 0)
        {
            if (myNode == hashTable[hashIndex].head)
                hashTable[hashIndex].head = myNode->next;
            else
                temp->next = myNode->next;
            hashTable[hashIndex].count--;
            free(myNode);
            break;
        }
        temp = myNode;
        myNode = myNode->next;
    }
    if (flag)
        printf("Data deleted successfully from Hash Table\n");
    else
        printf("Data is not available in hash Table\n");
    return;
}

// this function does a hash lookup input being the username
// Reference http://see-programming.blogspot.de/2013/05/chain-hashing-separate-chaining-with.html
bool authenticate(char *username, char *password)
{
    bool flag = false;
    unsigned long long int hashVal = hashFunction(username);
    int hashIndex = hashVal % TOTAL_ROW;
    printf("\nEntered username and password hash index = %d\n ", hashIndex);
    struct Node *myNode;
    myNode = hashTable[hashIndex].head;
    if (!myNode)
    {
        printf("Search element not available in hash table\n");
        return flag;
    }
    else
    {
        while (myNode != NULL)
        {
            if (strcasecmp(myNode->password,password) == 0)
            {
                flag = true;
                break;
            }
            myNode = myNode->next;
        }
        if (!flag)
            printf("Data is not available in hash Table\n");
        else
            printf("Data found\n");
    }
    return flag;
}

// this function creates the hash table with username being key
// and password being the value.
// Reference http://stackoverflow.com/questions/13390133/read-name-value-pairs-from-a-file-in-c
void createHashTable()
{
    char *username, *password;
    char *delimiter = ":";
    // file name in windows format, when running in linux, use '/'
    const char filename[] = "./passwd";
    // opening file in read (r) mode
    FILE *file = fopen ( filename, "r" );
    if ( file != NULL )
    {
        // allocating max 128 bytes for <key,value> pairs
        char file_lines[128];
        while ( fgets ( file_lines, sizeof file_lines, file ) != NULL )
        {
            // strtok method to split the read line from file based on a delimiter
            username = strtok(file_lines, delimiter);
            password = strtok(NULL, "\r");
            insertToHash(username, password);
        }
        fclose ( file );
    }
    else
    {
        printf("\n Unable to read file.");
    }
    return;
}

// this function checks if the input values exist in the
// hash table and returns bool.true if yes else bool.false
int auth(char * username, char * password)
{
    hashTable = (struct Hash *)calloc(TOTAL_ROW, sizeof (struct Hash));
    createHashTable();
    return(authenticate(username, password));
}
