///////////////////////////////////////////////////////////////////////////////
/*
    passkey
    Author: Norbert Vegh, vegh-&-norvegh.com
    (C) 2015,  Norbert Vegh
*/
///////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <pwd.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <X11/Xutil.h>
#include <openssl/aes.h>

using namespace std;

#define VERSION 0.1
#define PIDFILE "/var/lock/passkey.pid"

///////////////////////////////////////////////////////////////////////////////

// global data
string home;  // the user's home directory
string pwd;  // our encryption password
int encrypted = 0;

// shortcut trigger
struct Trigger
{
    int key;  // pressed key
    int mods;  // modifications: CTRL, ALT, SHIFT, WIN
};

// shortcut action
struct Action
{
    string desc;  // description
    string pwd;  // password
};

inline bool operator<( const Trigger &left, const Trigger &right )
{
   if( left.key < right.key ) return -1;
   if( left.key > right.key ) return 0;
   if( left.mods < right.mods ) return -1;
   return 0;
}

typedef map< Trigger, Action > Shortcuts;
Shortcuts shortcuts;

// global functions
int get_daemon_pid();
void cleanup();
void sig_handler( int sig );
int start_daemon();
string write_mods( unsigned int mods );
int read_trigger( string field, Trigger &trigger );
int read_data();
string read_pwd();
int print_data();
int write_data();
int encrypt_data( string pwd, string &buffer );
int decrypt_data( string pwd, string &buffer );
int usage();


///////////////////////////////////////////////////////////////////////////////
int main( int argc, char **argv )
{
    int pid;
    unsigned int i, n;
    string line;
    struct passwd *pw;
    Trigger trigger;
    Action action;
    Shortcuts::iterator iter;

    // check config directories
    pw = getpwuid(getuid());
    home = pw->pw_dir;
    // process arguments
    if( argc == 1 )
    {
        if( read_data() )
        {
            return -1;
        }
        return start_daemon();
    }
    if( argc != 2 ) usage();
    // list entries
    if( !strcmp( argv[1], "-l" ) )
    {

        if( read_data() )
        {
            return -1;
        }
        print_data();
        return 0;
    }
    // add a new entry
    if( !strcmp( argv[1], "-a" ) )
    {
        if( read_data() )
        {
            return -1;
        }
        cout << "Enter trigger key: ";
        getline( cin, line );
        if( read_trigger( line, trigger ) )
        {
            cout << "Invalid key.\n";
            return -1;
        }
        cout << "Enter description: ";
        getline( cin, line );
        action.desc = line;
        cout << "Enter password: ";
        action.pwd = read_pwd();
        cout << endl;
        cout << "Retype password: ";
        line = read_pwd();
        cout << endl;
        if( line != action.pwd )
        {
            cout << "Passwords do not match.\n";
            return -1;
        }
        shortcuts[trigger] = action;
        if( write_data() )
        {
            return 0;
        }
        cout << "Entry added.\n";
        pid = get_daemon_pid();
        if( pid > 1 )
        {
            // restart daemon
            kill( pid, SIGTERM );
            usleep( 10000 );
            start_daemon();
        }
        return 0;
    }
    // delete an entry
    if( !strcmp( argv[1], "-d" ) )
    {
        if( read_data() )
        {
            return -1;
        }
        if( not shortcuts.size() )
        {
            cout << "No entries.\n";
            return 0;
        }
        print_data();
        cout << "Enter the number of the entry to delete it: ";
        cin >> n;
        if( n < 1 or n > shortcuts.size() )
        {
            cout << "Invalid input.\n";
            return -1;
        }
        for( i = 1, iter = shortcuts.begin(); i < n; i++, iter++ );
        shortcuts.erase( iter );
        if( not write_data() )
        {
            cout << "Entry " << n << ". deleted.\n";
        }
        pid = get_daemon_pid();
        if( pid > 1 )
        {
            // restart daemon
            kill( pid, SIGTERM );
            usleep( 10000 );
            start_daemon();
        }
        return 0;
    }
    // stop daemon
    if( !strcmp( argv[1], "-s" ) )
    {
        pid = get_daemon_pid();
        if( pid < 2 )
        {
            return -1;
        }
        kill( pid, SIGTERM );
        return 0;
    }
    // encrypt the data file
    if( !strcmp( argv[1], "--encrypt" ) )
    {
        if( read_data() )
        {
            return -1;
        }
        cout << "Enter new password: ";
        pwd = read_pwd();
        cout << endl;
        cout << "Retype new password: ";
        line = read_pwd();
        cout << endl;
        if( pwd != line )
        {
            cout << "Passwords do not match.\n";
            return 0;
        }
        encrypted = -1;
        if( write_data() )
        {
            return -1;
        }
        cout << "Data file encrypted.\n";
        return 0;
    }
    // decrypt the data file
    if( !strcmp( argv[1], "--decrypt" ) )
    {
        if( read_data() )
        {
            return -1;
        }
        encrypted = 0;
        if( write_data() )
        {
            return -1;
        }
        cout << "Data file decrypted.\n";
        return 0;
    }
    usage();
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int get_daemon_pid()
{
    int pid;
    ifstream pid_file;

    if( access( PIDFILE, F_OK ) )
    {
        cout << "ERROR: the daemon is not running.\n";
        cout << "File " << PIDFILE << " missing.\n";
        return -1;
    }
    pid_file.open( PIDFILE, ios::in );
    pid_file >> pid;
    pid_file.close();
    if( pid < 2 )
    {
        cout << "ERROR: bad pidfile (" << PIDFILE << ").\n";
        return -1;
    }
    return pid;
}


///////////////////////////////////////////////////////////////////////////////
void cleanup()
{
    unlink( PIDFILE );
//     if( disp )
//     {
//         XCloseDisplay( disp );
//         disp = 0;
//     }
    exit( 0 );
}


///////////////////////////////////////////////////////////////////////////////
void sig_handler( int sig )
{
    if( sig == SIGTERM )
    {
        exit( 0 );  // this will trigger cleanup
    }
}


///////////////////////////////////////////////////////////////////////////////
int start_daemon()
{
    int revert;
    unsigned int i;
    pid_t child;
    Display *disp;
    Window win_root, win_focus;
    XEvent event_in;
    XKeyEvent event_out;
    string str_pid, pwd;
    ofstream pid_file;
    Trigger trigger;
    Shortcuts converted;
    Shortcuts::iterator iter;
    struct sigaction sigact;
    string upper_keys = "~!@#$%^&*()_+{}|:\">?";

    child = fork();
    if( child < 0 )
    {
        cout << "ERROR: could not fork\n";
        return -1;
    }
    if( child  )
    {
        return 0;
    }
    // set handler for SIGHUP which triggers data reload
    memset( &sigact, 0, sizeof( sigact ) );
    sigact.sa_handler = sig_handler;
    if( sigaction( SIGTERM, &sigact, 0 ) )
    {
        cout << "ERROR: could not set signal handler for SIGTERM\n";
        return -1;
    }
    // write our pid
    if( access( PIDFILE, F_OK ) != -1 )
    {
        cout << "ERROR: a daemon is already running.\n";
        cout << "Please check, and if it is dead, than remove " << PIDFILE << ".\n";
        return -1;
    }
    pid_file.open( PIDFILE, ios::out );
    pid_file << getpid();
    if( not pid_file )
    {
        cout << "ERROR: could not write " << PIDFILE << ".\n";
        return -1;
    }
    pid_file.close();
    atexit( cleanup );
    disp = XOpenDisplay( 0 );
    win_root = DefaultRootWindow( disp );
    // need to convert the keys to keycodes
    for( iter = shortcuts.begin(); iter != shortcuts.end(); iter++ )
    {
        trigger = iter->first;
        trigger.key = XKeysymToKeycode( disp, ( KeySym )trigger.key );
        converted[trigger] = iter->second;
    }
    // grab the keys
    for( iter = converted.begin(); iter != converted.end(); iter++ )
    {
        trigger = iter->first;
        XGrabKey( disp, trigger.key, trigger.mods, win_root, True, GrabModeAsync, GrabModeAsync );
    }
    XSelectInput( disp, win_root, KeyReleaseMask );
    fclose( stdin );
    fclose( stdout );
    fclose( stderr );
    while( true )
    {
        XNextEvent( disp, &event_in );  // this blocks signals
        if( event_in.type == 3 )
        {
            trigger.key = event_in.xkey.keycode;
            trigger.mods = event_in.xkey.state;
            iter = converted.find( trigger );
            if( iter == converted.end() )
            {
                // no shortcut for this
                continue;
            }
            pwd = iter->second.pwd;
            // clear event queue
            while( XPending( disp ) )
            {
                XNextEvent( disp, &event_in );
            }
            // send password to active window
            XGetInputFocus( disp, &win_focus, &revert );
            event_out.display = disp;
            event_out.window = win_focus;
            event_out.root = win_root;
            event_out.subwindow = None;
            event_out.x = 1;
            event_out.y = 1;
            event_out.x_root = 1;
            event_out.y_root = 1;
            event_out.same_screen = True;
            event_out.state = 0;
            for( i = 0; i < pwd.size(); i++ )
            {
                event_out.type = KeyPress;
                event_out.time = CurrentTime;
                // i have no idea why it has to work like this...
                if( isupper( pwd[i] ) or upper_keys.find( pwd[i] ) != string::npos )
                {
                    event_out.state = ShiftMask;
                }
                else
                {
                    event_out.state = 0;
                }
                event_out.keycode = XKeysymToKeycode( disp, pwd[i] );
                XSendEvent( disp, win_focus, True, KeyPressMask, ( XEvent * )&event_out );
                event_out.type = KeyRelease;
                event_out.time = CurrentTime;
                XSendEvent( disp, win_focus, True, KeyPressMask, ( XEvent * )&event_out );
            }
        }
    }
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int read_trigger( string field, Trigger &trigger )
{
    unsigned int mods;

    mods = 0;
    while( true )
    {
        if( not field.compare( 0, 5, "CTRL+" ) )
        {
            mods |= ControlMask;
            field = field.substr( 5 );
        }
        else if( not field.compare( 0, 4, "ALT+" ) )
        {
            mods |= Mod1Mask;
            field = field.substr( 4 );
        }
        else if( not field.compare( 0, 6, "SHIFT+" ) )
        {
            mods |= ShiftMask;
            field = field.substr( 6 );
        }
        else if( not field.compare( 0, 4, "WIN+" ) )
        {
            mods |= Mod4Mask;
            field = field.substr( 4 );
        }
        else
        {
            break;
        }
    }
    if( field.size() != 1 )
    {
        // invalid syntax
        return -1;
    }
    trigger.key = field[0];
    trigger.mods = mods;
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int read_data()
{
    unsigned int i, sep;
    uint32_t chsum, carry, chsum2;
    string data, line, key;
    ifstream datafile;
    stringstream buffer;
    Trigger trigger;
    Action action;
    struct stat statinfo;

    encrypted = 0;
    shortcuts.clear();
    if( stat( ( home + "/.passkey" ).c_str(), &statinfo ) )
    {
        // no file
        return 0;
    }
    datafile.open( ( home + "/.passkey" ).c_str(), ios::in | ios::binary );
    if( not datafile )
    {
        cout << "ERROR: could not open ~/.passkey for reading.\n";
        return -1;
    }
    // read the whole file into buffer
    buffer << datafile.rdbuf();
    datafile.close();
    data = buffer.str();
    // check for encryption
    if( data.substr( 0, 10 ) == "ENCRYPTED\n" )
    {
        encrypted = -1;
        data = data.substr( 10 );
        cout << "Enter password: ";
        pwd = read_pwd();
        cout << endl;
        decrypt_data( pwd, data );
        // verify checksum
        sep = data.find( '\n' );
        if( sep == string::npos or sep < 1 )
        {
            cout << "ERROR: bad password\n";
            return -1;
        }
        buffer.str( data.substr( 0, sep ) );
        buffer >> chsum2;
        chsum = 0;
        data = data.substr( sep + 1);
        for( i = 0; i < data.size(); i++ )
        {
            chsum += ( int )data[i];
            carry = chsum >> 31;
            chsum <<= 1;
            chsum += carry;
        }
        if( chsum != chsum2 )
        {
            cout << "ERROR: bad password\n";
            return -1;
        }
        buffer.clear();
        buffer.str( data );
    }
    // now read entries line by line
    while( true )
    {
        while( getline( buffer, key ) )
        {
            if( key.size() ) break;
        }
        if( buffer.eof() )
        {
            break;
        }
        while( getline( buffer, action.desc ) )
        {
            if( action.desc.size() ) break;
        }
        if( buffer.eof() )
        {
            break;
        }
        action.pwd = "";
        while( getline( buffer, action.pwd ) )
        {
            if( action.pwd.size() ) break;
        }
        if( not action.pwd.size() )
        {
            break;
        }
        if( read_trigger( key, trigger ) )
        {
            continue;
        }
        shortcuts[trigger] = action;
    }
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
string read_pwd()
{
    string pwd;
    struct termios term_old, term_new;

    // disable echo
    tcgetattr( STDIN_FILENO, &term_old );
    term_new = term_old;
    term_new.c_lflag &= ~ECHO;
    tcsetattr( STDIN_FILENO, TCSANOW, &term_new );
    getline( cin, pwd );
    tcsetattr( STDIN_FILENO, TCSANOW, &term_old );
    return pwd;
}


///////////////////////////////////////////////////////////////////////////////
string write_mods( unsigned int mods )
{
    string out;

    if( mods & ControlMask )
    {
        out += "CTRL+";
    }
    if( mods & Mod1Mask )
    {
        out += "ALT+";
    }
    if( mods & ShiftMask )
    {
        out += "SHIFT+";
    }
    if( mods & Mod4Mask )
    {
        out += "WIN+";
    }
    return out;
}

///////////////////////////////////////////////////////////////////////////////
int print_data()
{
    int i;
    Trigger trigger;
    Shortcuts::iterator iter;

    if( shortcuts.size() == 0 )
    {
        cout << "No entries.\n";
        return 0;
    }
    for( i = 1, iter = shortcuts.begin(); iter != shortcuts.end(); i++, iter++ )
    {
        cout << i << ". ";
        trigger = iter->first;
        cout << write_mods( trigger.mods );
        cout << ( char )trigger.key << ": " << iter->second.desc << endl;
    }
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int write_data()
{
    unsigned int i, len;
    uint32_t chsum, carry;
    ofstream datafile;
    Trigger trigger;
    Shortcuts::iterator iter;
    ostringstream buffer;
    string data;

    datafile.open( ( home + "/.passkey" ).c_str(), ios::out | ios::binary );
    if( not datafile )
    {
        cout << "ERROR: cannot open ~/.passkey for writing.\n";
        return -1;
    }
    for( iter = shortcuts.begin(); iter != shortcuts.end(); iter++ )
    {
        trigger = iter->first;
        buffer << write_mods( trigger.mods ) << ( char )trigger.key << endl;
        buffer << iter->second.desc << endl;
        buffer << iter->second.pwd << endl << endl;
    }
    data = buffer.str();
    if( encrypted )
    {
        // calculate checksum
        len = data.size();
        chsum = 0;
        for( i = 0; i < len; i++ )
        {
                chsum += ( int )data[i];
                carry = chsum >> 31;
                chsum <<= 1;
                chsum += carry;
        }
        // place it into the data
        buffer.str( "" );
        buffer << chsum << endl;
        data = buffer.str() + data;
        // now encrypt it
        encrypt_data( pwd, data );
        data = "ENCRYPTED\n" + data;
    }
    datafile << data;
    datafile.close();
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int encrypt_data( string pwd, string &data )
{
    int i, len, fill;
    const unsigned char *datap;
    unsigned char buffer[16];
    timeval now;
    AES_KEY key;
    unsigned char upwd[16];

    memset( upwd, 0, 16 );
    len = pwd.size();
    if( len > 16 )
    {
        len = 16;
    }
    memcpy( upwd, pwd.c_str(), len );

    // add a terminating 0 so the decoder will know where the data ends
    data += '\0';
    len = data.size();
    // add random dummy bytes for 16 bytes allignement
    gettimeofday( &now, 0 );
    srand( now.tv_usec );
    fill = len/16*16;
    if( fill < len )
    {
        fill += 16;
    }
    fill -= len;
    for( i = 0; i < fill; i++ )
    {
        data += rand()%256;
    }
    datap = ( const unsigned char * )data.data();
    AES_set_encrypt_key( upwd, 128, &key );
    for( i = 0; i < len; i += 16 )
    {
        AES_encrypt( datap + i, buffer, &key );
        memcpy( ( void * )( datap + i ), buffer, 16 );
    }
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int decrypt_data( string pwd, string &data )
{
    int i, len;
    const unsigned char *datap;
    unsigned char buffer[16];
    AES_KEY key;
    unsigned char upwd[16];

    memset( upwd, 0, 16 );
    len = pwd.size();
    if( len > 16 )
    {
        len = 16;
    }
    memcpy( upwd, pwd.c_str(), len );
    len = data.size();
    datap = ( const unsigned char * )data.data();
    AES_set_decrypt_key( upwd, 128, &key );
    for( i = 0; i + 16 <= len; i += 16 )
    {
        AES_decrypt( datap + i, buffer, &key );
        memcpy( ( void * )( datap + i ), buffer, 16 );
    }
    data = data.c_str();  // use the terminating 0
    return 0;
}


///////////////////////////////////////////////////////////////////////////////
int usage()
{
    cout << "passkey (C) 2015, Norbert Vegh\n";
    cout << "The password automation tool.\n";
    cout << "Version " << VERSION << endl;
    cout << "Without any arguments the program will start as a daemon.\n";
    cout << "Otherwise the following arguments can be used, only one at a time:\n";
    cout << " -l   : list the currently configured triggers and their description\n";
    cout << " -a   : add a new entry (interactive mode)\n";
    cout << " -d   : delete an entry (interactive mode)\n";
    cout << " -s   : stop the daemon\n";
    cout << " --encrypt   : set or reset the master password and encrypt the data file\n";
    cout << " --decrypt   : decrypt the data file\n";
    cout << "\n";
    cout << "The data is stored in " << home << "/.passkey.\n";
    return -1;
}
