package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	log.SetLevel(log.InfoLevel)
	//log.SetFormatter(&log.JSONFormatter{})
	log.SetFormatter(&log.TextFormatter{})
	/*
	   	log.WithFields(log.Fields{
	     "event": event,
	     "topic": topic,
	     "key": key,
	   }).Fatal("Failed to send event")
	*/

	dbusername := flag.String("dbusername", "admin", "Mysql database username")
	dbpassword := flag.String("dbpassword", "admin", "Mysql database password")
	dbipv4address := flag.String("dbipv4address", "127.0.0.1", "Mysql IPv4 address")
	dbport := flag.Int("dbport", 3306, "Mysql port number")
	dbname := flag.String("dbname", "database", "Database name to access")
	dbprefixst := flag.String("dbprefixst", "SELECT prefix as prefix FROM blackholeprefixes", "SQL Select statment for retreving prefix, column name should be prefix")
	dbscantime := flag.Int("dbscantime", 30, "Database scantime for changes")
	flag.Parse()
	if net.ParseIP(*dbipv4address).To4() == nil {
		log.Printf("ERROR : %s is not a valid ipv4 address", dbipv4address)
		log.WithFields(log.Fields{
			"function": "main",
		}).Errorf("%s is not a valid ipv4 address", dbipv4address)
		os.Exit(1)
	}

	sqlconfig := MySQLConfig{Username: *dbusername, Password: *dbpassword, Host: *dbipv4address, Port: *dbport}
	dataSourceName := sqlconfig.dataStoreName(*dbname)
	log.Printf("INFO : sql config : %s", dataSourceName)
	db := sqlConnection(dataSourceName)
	// setup signal catching
	sigs := make(chan os.Signal, 1)
	// catch all signals since not explicitly listing
	signal.Notify(sigs)
	// signal.Notify(sigs,syscall.SIGQUIT)
	// method invoked upon seeing signal

	s := gobgp.NewBgpServer()
	go s.Serve()

	go func() {
		ossignal := <-sigs
		log.WithFields(log.Fields{
			"function": "main",
		}).Warnf("received signal from os : %s", ossignal)
		AppCleanup(db, s)
		os.Exit(1)
	}()

	// start grpc api server. this is not mandatory
	// but you will be able to use `gobgp` cmd with this.
	g := api.NewGrpcServer(s, ":50051")
	go g.Serve()

	// global configuration
	global := &config.Global{
		Config: config.GlobalConfig{
			As:       65000,
			RouterId: "10.2.8.12",
			//LocalAddressList : []string{"10.2.8.12"},
			Port: -1, // gobgp won't listen on tcp:179
		},
	}

	if err := s.Start(global); err != nil {
		log.WithFields(log.Fields{
			"function": "main",
		}).Fatalf("error while starting bgp server : %s", err)
		AppCleanup(db, s)
		os.Exit(1)
	}

	// neighbor configuration
	n := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "10.2.51.7",
			PeerAs:          65000,
		},
		AfiSafis: []config.AfiSafi{
			config.AfiSafi{
				Config: config.AfiSafiConfig{
					AfiSafiName: "ipv4-unicast",
				},
			},
			config.AfiSafi{
				Config: config.AfiSafiConfig{
					AfiSafiName: "l3vpn-ipv4-unicast",
				},
			},
		},
	}
	if err := s.AddNeighbor(n); err != nil {
		log.WithFields(log.Fields{
			"function": "main",
		}).Fatalf("error while adding bgp neighbor : %s", err)
		AppCleanup(db, s)
		os.Exit(1)
	}

	log.WithFields(log.Fields{
		"function": "main",
	}).Infof("route server started")

	// edit the code according to desired announce
	//labels to be used
	labels := bgp.NewMPLSLabelStack(100)

	rd, err := bgp.ParseRouteDistinguisher("1:1")
	if err != nil {
		log.WithFields(log.Fields{
			"function": "main",
		}).Errorf("error while creating route distinguisher : %s", err)
	}
	ecommunities := []bgp.ExtendedCommunityInterface{
		bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 1, 1, true),
	}

	var u chan map[string]string = make(chan map[string]string)
	var w chan map[string]string = make(chan map[string]string)

	go getRoutes(u, w, db, dbscantime, dbprefixst)

	for {

		//now get and announce routes
		select {
		case updatePrefixes := <-u:
			announcePathList := make([]*table.Path, 0, 0)
			for prefix, _ := range updatePrefixes {
				announcePathList = append(announcePathList, table.NewPath(nil, bgp.NewLabeledVPNIPAddrPrefix(32, prefix, *labels, rd), false, []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(0),
					bgp.NewPathAttributeAsPath(nil),
					bgp.NewPathAttributeExtendedCommunities(ecommunities),
					bgp.NewPathAttributeMpReachNLRI("10.2.8.12", []bgp.AddrPrefixInterface{bgp.NewLabeledVPNIPAddrPrefix(32, prefix, *labels, rd)}),
				}, time.Now(), false))

			}
			if _, err := s.AddPath("", announcePathList); err != nil {
				log.WithFields(log.Fields{
					"function": "main",
				}).Errorf("error while adding update routes : %s", err)
			}
		case withdrawPrefixes := <-w:
			announcePathList := make([]*table.Path, 0, 0)
			for prefix, _ := range withdrawPrefixes {
				announcePathList = append(announcePathList, table.NewPath(nil, bgp.NewLabeledVPNIPAddrPrefix(32, prefix, *labels, rd), true, []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(0),
					bgp.NewPathAttributeAsPath(nil),
					bgp.NewPathAttributeExtendedCommunities(ecommunities),
					bgp.NewPathAttributeMpReachNLRI("10.2.8.12", []bgp.AddrPrefixInterface{bgp.NewLabeledVPNIPAddrPrefix(32, prefix, *labels, rd)}),
				}, time.Now(), false))

			}

			if err := s.DeletePath(nil, bgp.RF_IPv4_VPN, "", announcePathList); err != nil {

				log.WithFields(log.Fields{
					"function": "main",
				}).Errorf("error while adding withdrawn routes : %s", err)
			}
		}

	}


}

// Stores the variables needed for MYSQL connection
type MySQLConfig struct {
	// Optional.
	Username, Password string

	// Host of the MySQL instance.
	//
	// If set, UnixSocket should be unset.
	Host string

	// Port of the MySQL instance.
	//
	// If set, UnixSocket should be unset.
	Port int

	// UnixSocket is the filepath to a unix socket.
	//
	// If set, Host and Port should be unset.
	UnixSocket string
}

// Returns a connection string suitable for sql.Open.
func (c MySQLConfig) dataStoreName(databaseName string) string {
	var cred string
	// [username[:password]@]
	if c.Username != "" {
		cred = c.Username
		if c.Password != "" {
			cred = cred + ":" + c.Password
		}
		cred = cred + "@"
	}

	if c.UnixSocket != "" {
		return fmt.Sprintf("%sunix(%s)/%s", cred, c.UnixSocket, databaseName)
	}
	return fmt.Sprintf("%stcp([%s]:%d)/%s", cred, c.Host, c.Port, databaseName)
}

// Creates and return db object to be used for sql operations
func sqlConnection(dataSourceName string) *sql.DB {
	for {
		db, err := sql.Open("mysql", dataSourceName)
		log.WithFields(log.Fields{
			"function": "sqlConnection",
		}).Infof("checking database driver with the given sql connection string %s", dataSourceName)
		if err != nil {
			log.WithFields(log.Fields{
				"function": "sqlConnection",
			}).Errorf("driver error, %s, will retry in 10s", err)
			time.Sleep(time.Duration(10) * time.Second)
			continue
		}
		err = db.Ping()
		if err != nil {
			log.WithFields(log.Fields{
				"function": "sqlConnection",
			}).Errorf("database connection error, %s, will retry in 10s", err)
			time.Sleep(time.Duration(10) * time.Second)
			continue
		}
		log.WithFields(log.Fields{
			"function": "sqlConnection",
		}).Infof("connect to the database")
		return db
	}
}

// Connects to the database and select routes, return prefixes to be added or removed
func getRoutes(u chan map[string]string, w chan map[string]string, db *sql.DB, dbscantime *int, dbprefixst *string) {
	//var update prefixChangeList
	currentPrefixes := make(map[string]string)
	//z := make(map[string]string)
	for {
		returnedPrefixes := make(map[string]string)
		updatePrefixes := make(map[string]string)
		withdrawPrefixes := make(map[string]string)
		err := db.Ping()
		for err != nil {
			log.WithFields(log.Fields{
				"function": "getRoutes",
			}).Errorf("database connection error, %s, will retry in 10s", err)
			err = db.Ping()
		}
		var (
			prefix string
		)
		rows, err := db.Query(*dbprefixst)
		if err != nil {
			log.WithFields(log.Fields{
				"function": "getRoutes",
			}).Errorf("error while query, %s", err)
		} else {
			defer rows.Close()
			for rows.Next() {
				err := rows.Scan(&prefix)
				if err != nil {
					log.WithFields(log.Fields{
						"function": "getRoutes",
					}).Errorf("cannot found prefix field in the returned colums: %s", err)
				}
				log.WithFields(log.Fields{
					"function": "getRoutes",
				}).Debugf("found prefix %s", prefix)
				returnedPrefixes[prefix] = "id?"
			}
			err = rows.Err()
			if err != nil {
				log.WithFields(log.Fields{
					"function": "getRoutes",
				}).Debugf("end of the list", err)

			}
		}

		for prefix, v := range returnedPrefixes {
			if _, ok := currentPrefixes[prefix]; ok != true {
				updatePrefixes[prefix] = "id?"
				currentPrefixes[prefix] = v
				log.WithFields(log.Fields{
					"function": "getRoutes",
				}).Debugf("new prefix %s:%s is added to the currentPrefixes", prefix, v)
			}
		}

		for prefix, v := range currentPrefixes {
			if _, ok := returnedPrefixes[prefix]; ok != true {
				delete(currentPrefixes, prefix)
				withdrawPrefixes[prefix] = "id?"
				log.WithFields(log.Fields{
					"function": "getRoutes",
				}).Debugf("new prefix %s:%s is added to the currentPrefixes", prefix, v)
			}
		}
		if len(updatePrefixes) != 0 {
			u <- updatePrefixes
		}
		if len(withdrawPrefixes) != 0 {

			w <- withdrawPrefixes
		}

		log.WithFields(log.Fields{
			"function": "getRoutes",
		}).Infof("about to sleep %d s before looping again", *dbscantime)

		time.Sleep(time.Duration(*dbscantime) * time.Second)
	}
}

// Bgp server

// Cleanup
func AppCleanup(db *sql.DB, bgpserver *gobgp.BgpServer) {
	log.WithFields(log.Fields{
		"function": "getRoutes",
	}).Infof("cleanup and exit!!!")
	bgpserver.Shutdown()
	db.Close()
}
