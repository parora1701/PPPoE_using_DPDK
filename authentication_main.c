#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

//******Hashing with Linear Chaining Program, Hashing function used is Larsen's hashing algorithm for simple strings******//

#define TOTAL_ROW 500

// pre-C99 bool type does not exist, so defining our own
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

struct Node * createNode(char *password)
{
    struct Node *newnode;
    newnode = (struct Node *)malloc(sizeof(struct Node));
    strcpy(newnode->password, password);
    newnode->next = NULL;
    return newnode;
}

// using 64-bit int to provide better collision resolution
unsigned long long int hashFunction(const char* s)
{
    unsigned long long int hashVal = 0l;
    while (*s)
    {
        hashVal = hashVal * 31  +  *s++;
    }
    return hashVal;
}

void insertToHash(char *username, char *password)
{
    unsigned long long int hashVal = hashFunction(username);
    int hashIndex = hashVal % TOTAL_ROW;
    // printf("\nhash index = %d\n ", hashIndex);
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
            //printf("%s\n", myNode->password);
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

// function definition
void createHashTable()
{
    char *username, *password;
    char *delimiter = ":";
    // path of the file must be changed as per the deployment
    const char filename[] = "/home/nfvlab/dpdk/data.txt";
    // opening file in read (r) mode
    FILE *file = fopen ( filename, "r" );
    if ( file != NULL )
    {
        // allocating max 128 bytes for <key,value> pairs
        char file_lines[128];
        while ( fgets ( file_lines, sizeof file_lines, file ) != NULL )
        {
            username = strtok(file_lines, delimiter);
            // printf("\n Username (read from file): %s", username);
            password = strtok(NULL, "\r");
            // printf("\n Password (read from file) : %s", password);
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

int main()
{
    /*
        free all allocated memory
    */
    char *username = malloc(sizeof(char));
    char *password = malloc(sizeof(char));
    hashTable = (struct Hash *)calloc(TOTAL_ROW, sizeof (struct Hash));
    createHashTable();
    printf(" Enter user name : ");
    scanf("%s", username);
    printf("\n Enter password : ");
    scanf("%s", password);
    printf("\n user input -> user name : %s and password : %s", username, password);
    printf("\nreturn result : %d \n", authenticate(username, password));
    free(username);
    free(password);
    free(hashTable);
    return 0;
}
