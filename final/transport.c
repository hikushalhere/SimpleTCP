/*
 * transport.c
 *
 * CS536 PA2 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define INIT_SEQUENCE_NUMBER_SPACE 256 /* the space withing which the initial sequence number should be present*/
#define WINDOW_SIZE 3072               /* maximum window size */
#define MAX_SEQUENCE_NUMBER 4294967296 /* this is 2^32 */
#define OFFSET 5                       /* default offset in TCP header */
#define HEADER_SIZE sizeof(STCPHeader) /* size of TCP header */
#define OPTIONS_SIZE 40                /* maximum size of TCP options */
#define TIMEOUT_INTERVAL 1             /* the value is in seconds */

/* Definition of the states of the connection */
typedef enum
{
    CSTATE_SEND_SYN = 0,
    CSTATE_WAIT_FOR_SYN,
    CSTATE_WAIT_FOR_SYN_ACK,
    CSTATE_WAIT_FOR_ACK,
    CSTATE_ESTABLISHED,
    CSTATE_SEND_FIN,
    CSTATE_FIN_RECVD,
    CSTATE_WAIT_FOR_FIN,
    CSTATE_CLOSED
} connection_state;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;                         /* TRUE once connection is closed */
    int connection_state;                /* state of the connection (established, etc.) */
    mysocket_t sd;                       /* socket descriptor */
    tcp_seq initial_sequence_num;        /* initial sequence number of this host */
    tcp_seq receiver_initial_seq_num;    /* initial sequence number of the receiver or the other host */

    tcp_seq receiver_window;             /* receiver window size last advertised by the receiver or the other host */

    tcp_seq send_base;                   /* first unACKed sequence number */
    tcp_seq send_base_ptr;               /* pointer to the send_window corresponding to the send window */
    tcp_seq next_sequence_num;           /* next sequence number that is free */

    tcp_seq recv_window_size;            /* current receive window of the host */
    tcp_seq expected_sequence_num_ptr;   /* pointer to the recv_window corresponding to the receive window */
    tcp_seq expected_sequence_num;       /* expected sequence number from the sender or other host */

    char send_window[WINDOW_SIZE];       /* send buffer of the host */
    char recv_window[WINDOW_SIZE];       /* receive buffer of the host */
    int recv_window_lookup[WINDOW_SIZE]; /* lookup table for the receive buffer of the host */

    bool_t timer_running;                /* to indicate whether the timer is running or not */
    int retransmission_count;            /* to keep a count of how many retransmissions have been done */
    bool_t close_initiator;              /* to indicate if the connection close has been initiated by this host or not */
} context_t;

/* function prototypes */
static void generate_initial_seq_num(context_t *);
static void control_loop(mysocket_t, context_t *);
STCPHeader *construct_header(tcp_seq);
char *extract_data_from_segment(char *, size_t, size_t);
void handle_app_data(char *, ssize_t, STCPHeader *, size_t);
void send_header(tcp_seq);
void buffer_sent_data(char *, size_t);
void resend(int);
void start_timer();
void stop_timer();
void transport_teardown();
size_t get_size_of_app_data(char *, ssize_t);
size_t get_send_window_size();
size_t buffer_recvd_data(size_t, char *, size_t);
size_t deliver_data_to_application();


/* declaring the context variable as global */
static context_t *ctx;


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    unsigned int event;
    unsigned int wait_flags;
    STCPHeader *recvd_header, *syn_header, *syn_ack_header, *ack_header;
    char *segment, *app_data;
    ssize_t segment_len;
    size_t app_data_len;
    struct timespec *abs_time;
    struct timeval  curr_time;
    int count;

    ctx = (context_t *) malloc(sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->sd = sd;

    recvd_header = syn_header = syn_ack_header = ack_header = NULL;
    segment      = app_data   = NULL;

    count = 0;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

     /* Passive side */
     if (!is_active)
     {
         ctx->connection_state = CSTATE_WAIT_FOR_SYN;
         count                 = 0;

         while(ctx->connection_state != CSTATE_ESTABLISHED)
         {
             switch(ctx->connection_state)
             {
                 /* Wait for SYN. Send SYN_ACK after receiving SYN */
                 case CSTATE_WAIT_FOR_SYN:
                        if(count == 0)
                        {
                            printf("\nWaiting for SYN");
                            wait_flags = 0 | NETWORK_DATA;
                            /* wait for the network to send data */
                            event = stcp_wait_for_event(sd, wait_flags, NULL);
                        }
                        else if(count == 6)
                        {
                            errno = ECONNREFUSED;
                            return;
                        }
                        else
                            event = 0 | NETWORK_DATA;

                        if (event & NETWORK_DATA)
                        {
                            printf("\nPreparing to send SYN-ACK");
                            /* allocate memory for receving data from network */
                            segment_len = HEADER_SIZE + OPTIONS_SIZE;
                            segment = (char *) malloc(segment_len * sizeof(char)); /* only expecting the header */
                            assert(segment);

                            /* receive data from netwrok */
                            segment_len = stcp_network_recv(sd, segment, segment_len);

                            /* get the pointer to the header in the segment received from the network */
                            recvd_header = (STCPHeader *) segment;

                            /* allocate memory for constructing the SYN_ACK header */
                            syn_ack_header = (STCPHeader *) malloc(HEADER_SIZE);
                            assert(syn_ack_header);
                            memset(syn_ack_header, 0, HEADER_SIZE);

                            /* construct the SYN_ACK header */
                            syn_ack_header->th_seq   = ctx->initial_sequence_num;
                            syn_ack_header->th_ack   = recvd_header->th_seq + 1;
                            syn_ack_header->th_flags = 0 | TH_SYN | TH_ACK;
                            syn_ack_header->th_win   = WINDOW_SIZE;
                            syn_ack_header->th_off   = OFFSET;

                            /* save the other host's initial sequence number */
                            ctx->receiver_initial_seq_num = recvd_header->th_seq;

                            /* send SYN_ACK */
                            /*if (stcp_network_send(sd, syn_ack_header, HEADER_SIZE, NULL) == -1)
                               errno = ECONNREFUSED;*/
                            /*else  change the connection state */
                            stcp_network_send(sd, syn_ack_header, HEADER_SIZE, NULL);
                            ctx->connection_state = CSTATE_WAIT_FOR_ACK;

                            /* free up memory */
                            if(syn_ack_header)
                            {
                                free(syn_ack_header);
                                syn_ack_header = NULL;
                            }
                            recvd_header = NULL;
                            if(segment)
                            {
                                free(segment);
                                segment = NULL;
                            }
                            printf("\nSYN-ACK sent");
                            count++;
                        }
                        break;

                 /* Wait for ACK. Unblock the application after receving ACK */
                 case CSTATE_WAIT_FOR_ACK:
                        printf("\nWaiting for ACK");
                        gettimeofday(&curr_time, NULL);
                        abs_time = (struct timespec *) (&curr_time);
                        abs_time->tv_sec += 2;
                        wait_flags = 0 | NETWORK_DATA;
                        /* wait for the network to send data */
                        event = stcp_wait_for_event(sd, wait_flags, abs_time);

                        if (event & NETWORK_DATA)
                        {
                            printf("\nPreparing to unblock the application");
                            /* allocate memory for receving data from network */
                            segment_len = HEADER_SIZE + OPTIONS_SIZE + STCP_MSS;
                            segment = (char *) malloc(segment_len * sizeof(char));
                            assert(segment);

                            /* receive data from netwrok */
                            segment_len = stcp_network_recv(sd, segment, segment_len);

                            /* get the pointer to the header in the segment received from the network */
                            recvd_header = (STCPHeader *) segment;

                            /* calculate the size of the data received */
                            app_data_len = get_size_of_app_data(segment, segment_len);
                            if(app_data_len > 0)
                            {
                                printf("\nACK with application data received");
                                /* handle the scenarios possible is there is data present in the segment */
                                handle_app_data(segment, segment_len, recvd_header, app_data_len);
                            }
                            /* change the connection state */
                            ctx->connection_state = CSTATE_ESTABLISHED;
                            recvd_header = NULL;
                            if(segment)
                            {
                                free(segment);
                                segment = NULL;
                            }
                            count = 0;
                        }
                        else
                            ctx->connection_state = CSTATE_WAIT_FOR_SYN;
                        break;

                default: break;
             }
         }
     }

     /* Active side */
     else
     {
         ctx->connection_state = CSTATE_SEND_SYN;
         count                 = 0;

         while(ctx->connection_state != CSTATE_ESTABLISHED)
         {
             switch(ctx->connection_state)
             {
                 case CSTATE_SEND_SYN:
                        if(count == 6)
                        {
                            errno = ECONNREFUSED;
                            return;
                        }
                        printf("\nPreparing to send SYN");
                        /* allocate memory for constructing the SYN header */
                        syn_header = (STCPHeader *) malloc(HEADER_SIZE);
                        assert(syn_header);
                        memset(syn_header, 0, HEADER_SIZE);

                        /* construct the syn header */
                        syn_header->th_seq   = ctx->initial_sequence_num;
                        syn_header->th_flags = 0 | TH_SYN;
                        syn_header->th_win   = WINDOW_SIZE;
                        syn_header->th_off   = OFFSET;

                        /* send SYN */
                        if (stcp_network_send(sd, syn_header, HEADER_SIZE, NULL) == -1)
                           errno = ECONNREFUSED;
                        else /* change the connection state */
                           ctx->connection_state = CSTATE_WAIT_FOR_SYN_ACK;

                        /* free up memory */
                        if(syn_header)
                        {
                            free(syn_header);
                            syn_header = NULL;
                        }
                        printf("\nSYN sent");
                        count++;
                        break;


                 case CSTATE_WAIT_FOR_SYN_ACK:
                        printf("\nWaiting for SYN-ACK");
                        gettimeofday(&curr_time, NULL);
                        abs_time = (struct timespec *) (&curr_time);
                        abs_time->tv_sec += 2;
                        wait_flags = 0 | NETWORK_DATA;
                        /* wait for the network to send data */
                        event = stcp_wait_for_event(sd, wait_flags, NULL);

                        if (event & NETWORK_DATA)
                        {
                            printf("\nPreparing to send ACK");
                            /* allocate memory for receving data from network */
                            segment_len = HEADER_SIZE + OPTIONS_SIZE;
                            segment = (char *) malloc(segment_len * sizeof(char));
                            assert(segment);

                            /* receive data from netwrok */
                            segment_len = stcp_network_recv(sd, segment, segment_len);

                            /* allocate memory for constructing the SYN_ACK header */
                            ack_header = (STCPHeader *) malloc(HEADER_SIZE);
                            assert(ack_header);
                            memset(ack_header, 0, HEADER_SIZE);

                            /* get the pointer to the header in the segment received from the network */
                            recvd_header = (STCPHeader *) segment;

                            /* construct the ACK header */
                            ack_header->th_seq   = ctx->initial_sequence_num;
                            ack_header->th_ack   = recvd_header->th_seq + 1;
                            ack_header->th_flags = 0 | TH_SYN | TH_ACK;
                            ack_header->th_win   = WINDOW_SIZE;
                            ack_header->th_off   = OFFSET;

                            /* save the other host's initial sequence number */
                            ctx->receiver_initial_seq_num = recvd_header->th_seq;

                            /* send SYN_ACK */
                            if (stcp_network_send(sd, ack_header, HEADER_SIZE, NULL) == -1)
                               errno = ECONNREFUSED;
                            else /* change the connection state */
                               ctx->connection_state = CSTATE_ESTABLISHED;

                            /* free up memory */
                            if(ack_header)
                            {
                                free(ack_header);
                                ack_header = NULL;
                            }
                            recvd_header = NULL;
                            if(segment)
                            {
                                free(segment);
                                segment = NULL;
                            }
                            printf("\nACK sent");
                            count = 0;
                        }
                        else
                            ctx->connection_state = CSTATE_SEND_SYN;
                        break;

                 default: break;
             }
         }
     }
     stcp_unblock_application(sd);
     printf("\nApplication unblocked");
     control_loop(sd, ctx);

    /* do any cleanup here */
    if(ctx)
    {
        free(ctx);
        ctx = NULL;
    }
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* generating a random number in the range 0-255 */
    ctx->initial_sequence_num = rand() % INIT_SEQUENCE_NUMBER_SPACE;
    printf("\nInitial sequence number is: %d", ctx->initial_sequence_num);
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    unsigned int event, wait_flags;
    char *segment, *app_data;
    size_t app_data_len, curr_send_window_left;
    ssize_t segment_len, bytes_sent;
    tcp_seq i;
    STCPHeader *header, *new_header;
    struct timespec *abs_time;
    struct timeval  curr_time;

    assert(ctx);

    /* initialize send_base and next_sequence_num */
    ctx->send_base         = ctx->initial_sequence_num + 1;
    ctx->send_base_ptr     = 0;
    ctx->next_sequence_num = ctx->initial_sequence_num + 1;

    /* initialize expected_sequence_num and recv_window_size */
    ctx->expected_sequence_num     = ctx->receiver_initial_seq_num + 1;
    ctx->expected_sequence_num_ptr = 0;
    ctx->recv_window_size          = WINDOW_SIZE;

    /* initialize timer_running status and the retransmission count */
    ctx->timer_running        = FALSE;
    ctx->retransmission_count = 0;

    /* initialize the host's status as !close_initiator */
    ctx->close_initiator = FALSE;

    /* initialize the recv_window_lookup table */
    for(i = 0; i < WINDOW_SIZE; i++)
        ctx->recv_window_lookup[i] = 0;

    /* initialize all the pointers to NULL */
    segment = app_data   = NULL;
    header  = new_header = NULL;

    printf("\nInitialization of STCP state variables and buffers complete");

    while (!ctx->done)
    {
        /* calculate the capacity left in the window */
        curr_send_window_left = get_send_window_size();

        printf("\n************************************************");
        printf("\nexpected_sequence_num    : %u", ctx->expected_sequence_num);
        printf("\nexpected_sequence_num_ptr: %u", ctx->expected_sequence_num_ptr);
        printf("\nrecv_window_size         : %u", ctx->recv_window_size);
        printf("\nsend_base                : %u", ctx->send_base);
        printf("\nsend_base_ptr            : %u", ctx->send_base_ptr);
        printf("\nnext_sequence_num        : %u", ctx->next_sequence_num);
        printf("\ncurrent send window size : %u", curr_send_window_left);
        printf("\n************************************************");

        if(curr_send_window_left <= 0)
            wait_flags = 0 | NETWORK_DATA;
        else
            wait_flags = 0 | ANY_EVENT;

        gettimeofday(&curr_time, NULL);
        abs_time = (struct timespec *) (&curr_time);
        abs_time->tv_sec += 2;

        /* wait for an event to occur */
        printf("\nWaiting for an event to occur");
        event = stcp_wait_for_event(sd, wait_flags, abs_time);

        bytes_sent = 0;

        if (event & TIMEOUT)
            continue; /* start over again and check for an event */

        /* app requesting data to be sent */
        /* only sender actions here */
        if (event & APP_DATA)
        {
            printf("\nEvent: Application wants to send data");

            /* window is  full. refuse to accept data from the application */
            if(curr_send_window_left > 0)
            {
                /* accept data from the application */
                if(curr_send_window_left < STCP_MSS)
                    app_data_len = curr_send_window_left;
                else
                    app_data_len = STCP_MSS;
                app_data = (char *) malloc(app_data_len * sizeof(char));
                app_data_len = stcp_app_recv(sd, app_data, app_data_len);
                printf("\nData accepted from application");

                /* construct the header */
                new_header = construct_header(ctx->next_sequence_num);

                /* allocate memory for segment to be sent to the network */
                segment_len = HEADER_SIZE + app_data_len;
                segment = (char *) malloc(segment_len * sizeof(char));

                /* copy the header to segment */
                memcpy(segment, new_header, HEADER_SIZE);

                /* copy the app_data to segment */
                memcpy(segment + HEADER_SIZE, app_data, app_data_len);

                /* send the segment to the network layer */
                do
                {
                    bytes_sent = stcp_network_send(sd, segment, segment_len, NULL);
                } while(bytes_sent == -1);
                printf("\nSTCP segment sent to the network layer");

                /* start the timer if it is not running */
                if(ctx->timer_running == FALSE)
                    start_timer();

                /* buffer the sent data into send_window */
                buffer_sent_data(app_data, app_data_len);
                printf("\nApplication data buffered");

                /* update next_sequence_num */
                ctx->next_sequence_num += app_data_len;
            }
        }

        /* network requesting data to be received */
        /* sender and receiver actions here */
        if (event & NETWORK_DATA)
        {
            printf("\nEvent: Network wants to deliver data");
            /* accept segment from network */
            segment_len = HEADER_SIZE + OPTIONS_SIZE + STCP_MSS;
            segment = (char *) malloc(segment_len * sizeof(char));
            segment_len = stcp_network_recv(sd, segment, segment_len);
            printf("\nSegment accepted from network layer");

            /* extract the header from the segment and convert to STCP structure */
            header = (STCPHeader *) segment;

            /* update the value of receiver's window */
            ctx->receiver_window = header->th_win;

            /* update the window according to the value of the ACK field */
            if(header->th_flags & TH_ACK)
            {
                printf("\nI got ACK %u", header->th_ack);
                if(header->th_ack > ctx->send_base && header->th_ack <= ctx->next_sequence_num)
                {
                    printf("\nThis ACK is within the send window");
                    /* update send_base_ptr */
                    ctx->send_base_ptr = (ctx->send_base_ptr + (header->th_ack - ctx->send_base)) % WINDOW_SIZE;

                    /* update send_base */
                    ctx->send_base = header->th_ack;

                    /* stop the timer if it is running */
                    if(ctx->timer_running == TRUE)
                        stop_timer();

                    /* start the timer if there are unACKed segments */
                    if(ctx->send_base < ctx->next_sequence_num && ctx->timer_running == FALSE)
                        start_timer();
                    printf("\nACK taken care of");
                }
            }

            /* calculate the length of app data */
            app_data_len = get_size_of_app_data(segment, segment_len);

            /* if the segment contains any data */
            /* then handle the various cases depending on the sequence number in the header */
            if(app_data_len > 0)
            {
                printf("\nSegment with application sequence number %u received", header->th_seq);
                /* handle the scenarios possible is there is data present in the segment */
                handle_app_data(segment, segment_len, header, app_data_len);
            }
            if(header->th_flags & TH_FIN)
            {
                printf("\nFIN received");
                printf("\nEvent: The other host wants to close the connection");
                ctx->connection_state = CSTATE_FIN_RECVD;
                ctx->close_initiator  = FALSE;
                transport_teardown();
                ctx->done = TRUE;
            }
        }

        /* connection close request */
        if (event & APP_CLOSE_REQUESTED)
        {
            printf("\nEvent: Application wants to close the connection");
            ctx->connection_state = CSTATE_SEND_FIN;
            ctx->close_initiator  = TRUE;
            transport_teardown();
            ctx->done = TRUE;
        }

        if(header)
            header = NULL;
        /* free up memory */
        if(segment)
        {
            free(segment);
            segment = NULL;
        }
        if(app_data)
        {
            free(app_data);
            app_data = NULL;
        }
        if(new_header)
        {
            free(new_header);
            new_header = NULL;
        }
    }
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}


/**
*** Additional functions for the implementation ***
**/

void handle_app_data(char *segment, ssize_t segment_len, STCPHeader *header, size_t app_data_len)
{
    size_t data_offset;
    char *app_data;

    /* if the sequence number of the arrived segment is the expected sequence number */
    /* then extract the data within the receive window and deliver it to the application */
    /* update the window according to the value of the ACK field */
    if(header->th_seq == ctx->expected_sequence_num)
    {
        printf("\nIf sequence number received is the expected sequence number");

        /* extract app_data */
        data_offset = 0;
        app_data = extract_data_from_segment(segment, data_offset, app_data_len);
        printf("\nApplication data extracted from the segment");

        /* buffer whatever has been received */
        app_data_len = buffer_recvd_data(ctx->expected_sequence_num_ptr, app_data, app_data_len);
        printf("\nReceived data buffered");

        /* deliver max possible data to the application */
        app_data_len = deliver_data_to_application();
        printf("\nReceived data delivered to application");

        /* update the STCP state variables */
        ctx->expected_sequence_num_ptr = (ctx->expected_sequence_num_ptr + app_data_len) % WINDOW_SIZE;
        ctx->expected_sequence_num    += app_data_len;
        ctx->recv_window_size         += app_data_len;
        if(ctx->recv_window_size > WINDOW_SIZE)
            ctx->recv_window_size = WINDOW_SIZE;
        printf("\nSTCP state variables updated");

        /* send the ACK */
        send_header(ctx->next_sequence_num);
        printf("\nACK sent");
    }
    /* if the sequence number of the arrived segment is less than the expected sequence number */
    /* then extract the data within the receive window and deliver it to the application */
    else if(header->th_seq < ctx->expected_sequence_num && header->th_seq >= ctx->expected_sequence_num - WINDOW_SIZE)
    {
        printf("\nIf sequence number is a previously received sequence number...");

        if(header->th_seq + app_data_len >= ctx->expected_sequence_num)
        {
            printf("\n...but received data lies inside the window");
            /* extract the data that falls in the window */
            data_offset  = ctx->expected_sequence_num - header->th_seq;
            app_data_len = app_data_len - data_offset;
            if(app_data_len > WINDOW_SIZE)
                app_data_len = WINDOW_SIZE;
            app_data = extract_data_from_segment(segment, data_offset, app_data_len);
            printf("\nData that lies in the window extracted");

            /* buffer whatever has been received */
            app_data_len = buffer_recvd_data(ctx->expected_sequence_num_ptr, app_data, app_data_len);
            printf("\nReceived data buffered");

            /* deliver max possible data to the application */
            app_data_len = deliver_data_to_application();
            printf("\nReceived data delivered to application");

            /* update the STCP state variables */
            ctx->expected_sequence_num_ptr = (ctx->expected_sequence_num_ptr + app_data_len) % WINDOW_SIZE;
            ctx->expected_sequence_num    += app_data_len;
            ctx->recv_window_size         += app_data_len;
            if(ctx->recv_window_size > WINDOW_SIZE)
                ctx->recv_window_size = WINDOW_SIZE;
            printf("\nSTCP state variables updated");

            /* send the ACK */
            send_header(ctx->next_sequence_num);
        }
        else
        {
            printf("\n...and the data is duplicate");
            /* send the ACK */
            send_header(ctx->next_sequence_num);
        }
    }
    /* if the sequence number of the arrived segment is within the receive window */
    /* then extract the data within the receive window and store it in the receive buffer */
    else if(header->th_seq > ctx->expected_sequence_num && header->th_seq < ctx->expected_sequence_num + WINDOW_SIZE)
    {
        printf("\nIf sequence number lies within the receive window");
        /* send ACK for the last correctly received segment */
        /* buffer the incoming segment if buffer space is left */
        if(ctx->recv_window_size > 0)
        {
            /* extract and send data to application layer */
            data_offset = 0;
            app_data = extract_data_from_segment(segment, data_offset, app_data_len);
            printf("\nApplication data extracted from the segment");

            /* calculate app_data_len so that app_data outdside window is not buffered */
            if(header->th_seq + app_data_len > ctx->expected_sequence_num + WINDOW_SIZE)
                app_data_len = ctx->expected_sequence_num + WINDOW_SIZE - header->th_seq;

            /* buffer app_data */
            app_data_len = buffer_recvd_data(ctx->expected_sequence_num_ptr + header->th_seq - ctx->expected_sequence_num, app_data, app_data_len);
            printf("\nReceived data buffered");

            /* update STCP state variables */
            if(app_data_len > 0)
            {
                ctx->recv_window_size -= MIN(app_data_len, ctx->recv_window_size);
                printf("\nSTCP state variables updated");
            }

            /* send the ACK */
            send_header(ctx->next_sequence_num);
        }
    }
}

void transport_teardown()
{
    STCPHeader *fin_header, *ack_header, *recvd_header;
    ssize_t segment_len, bytes_sent;
    size_t app_data_len;
    unsigned int event, wait_flags;
    char *segment;
    struct timespec *abs_time;
    struct timeval  curr_time;
    int count = 0;

    while(ctx->connection_state != CSTATE_CLOSED)
    {
        switch(ctx->connection_state)
        {
            case CSTATE_SEND_FIN:
                if(count == 6)
                {
                    errno = ECONNREFUSED;
                    return;
                }
                printf("\nPreparing to send FIN");
                /* allocate memory for constructing the FIN header */
                fin_header = (STCPHeader *) malloc(HEADER_SIZE);
                assert(fin_header);
                memset(fin_header, 0, HEADER_SIZE);

                /* construct the fin header */
                fin_header->th_seq   = ctx->next_sequence_num;
                fin_header->th_ack   = ctx->expected_sequence_num;
                fin_header->th_flags = 0 | TH_FIN;
                fin_header->th_win   = ctx->recv_window_size;
                fin_header->th_off   = OFFSET;

                /* send FIN */
                do
                {
                    bytes_sent = stcp_network_send(ctx->sd, fin_header, HEADER_SIZE, NULL);
                } while(bytes_sent == -1);

                /* change the connection state */
                ctx->connection_state = CSTATE_WAIT_FOR_ACK;

                /* free up memory */
                if(fin_header)
                {
                    free(fin_header);
                    fin_header = NULL;
                }
                printf("\nFIN sent");
                count++;
                break;

            case CSTATE_WAIT_FOR_ACK:
                printf("\nWaiting for ACK");
                gettimeofday(&curr_time, NULL);
                abs_time = (struct timespec *) (&curr_time);
                abs_time->tv_sec += 2;
                wait_flags = 0 | NETWORK_DATA;
                /* wait for the network to send data */
                event = stcp_wait_for_event(ctx->sd, wait_flags, abs_time);

                if (event & NETWORK_DATA)
                {
                    /* allocate memory for receving data from network */
                    segment_len = HEADER_SIZE + OPTIONS_SIZE + STCP_MSS;
                    segment = (char *) malloc(segment_len * sizeof(char));
                    assert(segment);

                    /* receive data from network */
                    segment_len = stcp_network_recv(ctx->sd, segment, segment_len);

                    /* get the pointer to the header in the segment received from the network */
                    recvd_header = (STCPHeader *) segment;

                    /* change the connection state */
                    if(recvd_header->th_flags & TH_ACK && recvd_header->th_ack == ctx->next_sequence_num + 1)
                    {
                        printf("\nACK received");
                        if(ctx->close_initiator)
                            ctx->connection_state = CSTATE_WAIT_FOR_FIN;
                        else
                            ctx->connection_state = CSTATE_CLOSED;
                        count = 0;
                    }
                    else
                        ctx->connection_state = CSTATE_SEND_FIN;
                    if(segment)
                    {
                        free(segment);
                        segment = NULL;
                    }
                }
                else
                    ctx->connection_state = CSTATE_SEND_FIN;
                break;

            case CSTATE_WAIT_FOR_FIN:
                printf("\nWaiting for FIN");
                gettimeofday(&curr_time, NULL);
                abs_time = (struct timespec *) (&curr_time);
                abs_time->tv_sec += 2;
                wait_flags = 0 | NETWORK_DATA;
                /* wait for the network to send data */
                event = stcp_wait_for_event(ctx->sd, wait_flags, abs_time);

                if(event & NETWORK_DATA)
                {
                    /* allocate memory for receving data from network */
                    segment_len = HEADER_SIZE + OPTIONS_SIZE + STCP_MSS;
                    segment = (char *) malloc(segment_len * sizeof(char));
                    assert(segment);

                    /* receive data from network */
                    segment_len = stcp_network_recv(ctx->sd, segment, segment_len);

                    /* get the pointer to the header in the segment received from the network */
                    recvd_header = (STCPHeader *) segment;

                    if(recvd_header->th_flags & TH_FIN)
                    {
                        stcp_fin_received(ctx->sd);
                        app_data_len = get_size_of_app_data(segment, segment_len);
                        if(app_data_len > 0)
                        {
                            printf("\nFIN segment with application data received");
                            /* handle the scenarios possible is there is data present in the segment */
                            handle_app_data(segment, segment_len, recvd_header, app_data_len);
                        }

                        /* change the connection state */
                        ctx->connection_state = CSTATE_FIN_RECVD;
                    }

                    /* free up memory */
                    if(segment)
                    {
                        free(segment);
                        segment = NULL;
                    }
                }

                break;

            case CSTATE_FIN_RECVD:
                printf("\nPreparing to send ACK");
                /* allocate memory for constructing the ACK header */
                ack_header = (STCPHeader *) malloc(HEADER_SIZE);
                assert(ack_header);
                memset(ack_header, 0, HEADER_SIZE);

                /* construct the ACK header */
                ack_header->th_seq   = ctx->next_sequence_num;
                ack_header->th_ack   = ctx->expected_sequence_num + 1;
                ack_header->th_flags = 0 | TH_ACK;
                ack_header->th_win   = ctx->recv_window_size;
                ack_header->th_off   = OFFSET;

                /* send ACK */
                do
                {
                    bytes_sent = stcp_network_send(ctx->sd, ack_header, HEADER_SIZE, NULL);
                } while(bytes_sent == -1);


                /* change the connection state */
                if(ctx->close_initiator)
                    ctx->connection_state = CSTATE_CLOSED;
                else
                    ctx->connection_state = CSTATE_SEND_FIN;

                /* free up memory */
                if(ack_header)
                {
                    free(ack_header);
                    ack_header = NULL;
                }
                printf("\nACK sent");
                break;

            default:
                break;
        }
    }
    printf("\nConnection closed. Bye!");
}

void send_header(tcp_seq seq_num)
{
    /* construct the header */
    STCPHeader *new_header = NULL;
    ssize_t bytes_sent;

    new_header = construct_header(seq_num);

    /* send ACK */
    do
    {
        bytes_sent = stcp_network_send(ctx->sd, new_header, HEADER_SIZE, NULL);
    }while(bytes_sent == -1);
    printf("\nACK %d sent to network layer", new_header->th_ack);

    /* free up memory */
    if(new_header)
    {
        free(new_header);
        new_header = NULL;
    }
}

void buffer_sent_data(char *app_data, size_t app_data_len)
{
    size_t next_seq_num_ptr, i, j;

    next_seq_num_ptr = (ctx->send_base_ptr + (ctx->next_sequence_num - ctx->send_base)) % WINDOW_SIZE;

    for(i = next_seq_num_ptr, j = 0; j < app_data_len; i = (i + 1) % WINDOW_SIZE, j++)
        ctx->send_window[i] = app_data[j];
}

size_t get_send_window_size()
{
    size_t curr_send_window_left;

    /* if the sequence number space has wrapped around */
    if(MAX_SEQUENCE_NUMBER - ctx->send_base < WINDOW_SIZE)
    {
        printf("\nWrap around!");
        /* if the send_base and next_sequence_number have not wrapped around */
        if(ctx->next_sequence_num > ctx->send_base)
            curr_send_window_left = (MAX_SEQUENCE_NUMBER - ctx->next_sequence_num) + (WINDOW_SIZE - (MAX_SEQUENCE_NUMBER - ctx->send_base));
        /* if the next_sequence_number has wrapped around */
        else
            curr_send_window_left = MAX_SEQUENCE_NUMBER - ctx->send_base + (ctx->next_sequence_num + 1);
    }
    /* no wrap around */
    else
    {
        printf("\nNo wrap around");
        curr_send_window_left = ctx->send_base + WINDOW_SIZE - ctx->next_sequence_num;
    }

    return curr_send_window_left;
}

size_t buffer_recvd_data(size_t start, char *app_data, size_t app_data_len)
{
    size_t i, j, bytes_delivered;

    start           = start % WINDOW_SIZE;
    bytes_delivered = 0;
    assert(app_data);

    printf("\n%u bytes to be buffered", app_data_len);
    for(i = start, j = 0; j < app_data_len; i = (i + 1) % WINDOW_SIZE, j++)
    {
        if(ctx->recv_window_lookup[i] == 0)
        {
            //printf("\nByte with window seq number %u has been buffered", i);
            ctx->recv_window[i]        = app_data[j];
            ctx->recv_window_lookup[i] = 1;
            bytes_delivered++;
        }
    }
    printf("\n%u bytes have been buffered", bytes_delivered);
    return bytes_delivered;
}

STCPHeader *construct_header(tcp_seq seq_num)
{
    STCPHeader *header = NULL;

    header = (STCPHeader *) malloc(HEADER_SIZE);
    assert(header);
    assert(ctx);
    memset(header, 0, HEADER_SIZE);

    header->th_seq   = seq_num;
    header->th_ack   = ctx->expected_sequence_num;
    header->th_flags = 0 | TH_ACK;
    header->th_off   = OFFSET;
    header->th_win   = ctx->recv_window_size;

    printf("\nNew ACK header constructed with sequence number: %u", seq_num);
    return header;
}

size_t deliver_data_to_application()
{
    size_t i, j, app_data_len;
    char *app_data;

    /* calculate the number of bytes that can be delivered */
    app_data_len = 0;
    i            = ctx->expected_sequence_num_ptr;
    while(ctx->recv_window_lookup[i] == 1 && app_data_len < WINDOW_SIZE)
    {
        i = (i + 1) % WINDOW_SIZE;
        app_data_len++;
    }

    /* create a buffer that can be used to deliver the data to application */
    app_data = (char *) malloc(app_data_len * sizeof(char));
    assert(app_data);

    /* store the data to be delivered in app_data */
    /* update the recv_buffer_lookup table */
    for(i = ctx->expected_sequence_num_ptr, j = 0; j < app_data_len; i = (i + 1) % WINDOW_SIZE, j++)
    {
        app_data[j]                = ctx->recv_window[i];
        ctx->recv_window_lookup[i] = 0;
    }

    /* deliver data to the application */
    stcp_app_send(ctx->sd, app_data, app_data_len);

    /* free up memory */
    if(app_data)
    {
        free(app_data);
        app_data = NULL;
    }
    printf("\n%u bytes delivered to application", app_data_len);
    return app_data_len;
}

char *extract_data_from_segment(char *segment, size_t data_offset, size_t app_data_len)
{
    size_t data_start_point;
    char *app_data;

    assert(segment);

    /* allocate memory to store the extracted application data */
    app_data = (char *) malloc(app_data_len * sizeof(char));
    assert(app_data);

    /* calculate the point in segment where to start the extraction from */
    data_start_point = TCP_DATA_START(segment) + data_offset;

    /* copy the application data from segment to app_data */
    memcpy(app_data, segment + data_start_point, app_data_len);

    printf("\nData extracted from byte number: %u", data_start_point);

    return app_data;
}

void resend(int sig)
{
    size_t app_data_len, offset, i, j, length;
    ssize_t segment_len, bytes_sent;
    char *segment, *app_data;
    STCPHeader *header;

    if(ctx->retransmission_count == 6)
    {
        printf("\nI am tired of trying. Later!");
        ctx->timer_running = FALSE;
        ctx->done          = TRUE;
        return;
    }
    printf("\nRetransmitting unACKed bytes after timeout");
    assert(ctx);

    if(ctx->timer_running == TRUE)
        ctx->timer_running = FALSE;

    ctx->retransmission_count++;
    printf("\nTransmission count: %d", ctx->retransmission_count);

    header  = NULL;
    segment = app_data = NULL;
    length  = ctx->next_sequence_num - ctx->send_base;
    offset  = 0;

    while(length > 0)
    {
        printf("\nResending unACKed segment with sequence number: %u", ctx->send_base + offset);
        /* determine the size of application data to be resent */
        if(length >= STCP_MSS)
            app_data_len = STCP_MSS;
        else
            app_data_len = length;

        /* allocate memory for app_data */
        app_data = (char *) malloc(app_data_len * sizeof(char));
        assert(app_data);

        /* construct the header */
        header = construct_header(ctx->send_base + offset);
        assert(header);

        /* allocate memory for the segment to be sent */
        segment_len = HEADER_SIZE + app_data_len;
        segment     = (char *) malloc(segment_len * sizeof(char));
        assert(segment);

        /* extract the data to be sent from send_buffer */
        for(i = (ctx->send_base_ptr + offset) % WINDOW_SIZE, j = 0; j < app_data_len; i = (i + 1) % WINDOW_SIZE, j++)
            app_data[j] = ctx->send_window[i];

        /* copy the header to segment */
        memcpy(segment, header, HEADER_SIZE);

        /* copy the app_data to segment */
        memcpy(segment + HEADER_SIZE, app_data, app_data_len);

        /* send the segment to network layer */
        do
        {
            bytes_sent = stcp_network_send(ctx->sd, segment, segment_len, NULL);
        }while(bytes_sent == -1);

        /* start the timer if it is not running */
        if(ctx->timer_running == FALSE)
            start_timer();

        /* free up memory */
        if(header)
        {
            free(header);
            header = NULL;
        }
        if(segment)
        {
            free(segment);
            segment = NULL;
        }
        if(app_data)
        {
            free(app_data);
            app_data = NULL;
        }

        /* update offset and length for the next chunk of data to be resent */
        offset += app_data_len;
        length -= MIN(app_data_len, length);
    }
}

void start_timer()
{
    struct sigaction sa;

    /* set the signal handler */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = resend;
    sigaction(SIGALRM, &sa, NULL);

    /* set the alarm */
    ctx->timer_running = TRUE;
    alarm(TIMEOUT_INTERVAL);
    printf("\nTimer started");
}

void stop_timer()
{
    /* switch off the alarm */
    ctx->timer_running        = FALSE;
    ctx->retransmission_count = 0;
    alarm(0);
    printf("\nTimer stopped");
}

size_t get_size_of_app_data(char *segment, ssize_t segment_len)
{
    size_t app_data_len;

    assert(segment);

    if(TCP_OPTIONS_LEN(segment) == 0)
        app_data_len = segment_len - HEADER_SIZE;
    else
        app_data_len = segment_len - (HEADER_SIZE + TCP_OPTIONS_LEN(segment));

    return app_data_len;
}
