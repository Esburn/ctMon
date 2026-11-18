package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/wneessen/go-mail"
	_ "modernc.org/sqlite"
)

type sender struct {
	Email string `json:"email"`
}

type target struct {
	Url  string `json:"url"`
	Port string `json:"port"`
}

type Conf struct {
	Host       string   `json:"smtpHost"`
	Port       int      `json:"smtpPort"`
	Sender     string   `json:"smtpSender"`
	Pass       string   `json:"smtpPass"`
	Subject    string   `json:"smtpSubject"`
	Recipients []sender `json:"smtpRecipients"`
	Addrs      []target `json:"addrs"`
}

type Cert struct {
	addr     string
	hash     []byte
	issuer   string
	notAfter string
}

func main() {
	confPrt := flag.String("conf", "./conf.json", "conf json file")
	flag.Parse()

	data, err := os.ReadFile(*confPrt)
	if err != nil {
		log.Fatal(err)
	}

	var conf Conf
	if err := json.Unmarshal(data, &conf); err != nil {
		log.Fatalf("Parse err: %v", err)
	}

	var changedAddr []string
	for _, c := range conf.Addrs {

		complAddr := c.Url + ":" + c.Port

		conn, dialErr := tls.Dial("tcp", complAddr, &tls.Config{ServerName: c.Url})
		if dialErr != nil {
			log.Fatal(dialErr)
		}
		leaf := conn.ConnectionState().PeerCertificates[0]
		if leaf != nil {
			//fmt.Printf("%x\n%s, %s", hash, leaf.Issuer, leaf.NotAfter)
			db, opErr := sql.Open("sqlite", "./crt.db")
			if opErr != nil {
				log.Fatal(opErr)
			}
			defer db.Close()
			_, exErr := db.Exec(`create table if not exists certs (
			id integer primary key autoincrement,
			addr text not null unique,
			hash blob not null check (length(hash) = 32),
			issuer text not null,
			notAfter text not null
		)`)
			if exErr != nil {
				log.Fatal(exErr)
			}
			hash := sha256.Sum256(leaf.Raw)
			if match, err := matchHash(db, complAddr, hash); err != nil {
				log.Fatal(err)
			} else {
				if match {
					log.Print("\n\tcontinue")
					continue
				} else {
					changedAddr = append(changedAddr, complAddr)
					//send mail
				}
			}

			id, insErr := upsert(db, complAddr, leaf, hash)
			if insErr != nil {
				log.Fatal(insErr)
			}
			log.Printf("url: %s\ntracked on id: %d", complAddr, id)

		}
	}
	if len(changedAddr) > 0 {
		sendMail(changedAddr, conf)
	}
}

func upsert(db *sql.DB, addr string, leaf *x509.Certificate, hash [32]byte) (id int64, err error) {
	query := `insert into certs (addr, hash, issuer, notAfter) 
	values (?, ?, ?, ?)
	on conflict(addr) do update set hash = excluded.hash, issuer = excluded.issuer, notAfter = excluded.notAfter;`

	res, err := db.Exec(query, addr, hash[:], leaf.Issuer.CommonName, leaf.NotAfter)
	if err != nil {
		return -1, err
	}
	if rc, _ := res.RowsAffected(); rc > 0 {
		id, _ = res.LastInsertId()
		return id, err
	} else {
		return -1, nil
	}
}

func matchHash(db *sql.DB, addr string, hash [32]byte) (match bool, err error) {
	query := `select hash, issuer, notAfter from certs where addr = ?`
	crtInfo := db.QueryRow(query, addr)
	var c Cert
	scanErr := crtInfo.Scan(&c.hash, &c.issuer, &c.notAfter)
	if scanErr != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // No matching user found
		}
		return false, scanErr
	}

	return hashesMatch(c.hash[:], hash[:]), nil
}

func hashesMatch(hash1, hash2 []byte) bool {
	// ConstantTimeCompare returns 1 if the two slices are equal, 0 otherwise.
	// It automatically returns 0 if the lengths are different.
	return subtle.ConstantTimeCompare(hash1, hash2) == 1
}

func sendMail(changes []string, c Conf) error {

	m := mail.NewMsg()
	if err := m.From(c.Sender); err != nil {
		log.Fatalf("No pude set el From addr: %s", err)
	}

	for _, r := range c.Recipients {
		if err := m.AddTo(r.Email); err != nil {
			log.Fatalf("No pude set el From addr: %s", err)
		}
	}

	m.Subject(c.Subject)

	body := "Los certificados de las siguientes páginas han cambiado:\n"
	for _, s := range changes {
		body += strings.Split(s, ":")[0] + "\n"
	}

	m.SetBodyString(mail.TypeTextPlain, body)

	mc, err := mail.NewClient(
		c.Host,
		mail.WithPort(c.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(c.Sender),
		mail.WithPassword(c.Pass),
	)

	if err != nil {
		log.Fatalf("Err creando el mail client: %s", err)
	}
	if err := mc.DialAndSend(m); err != nil {
		log.Fatalf("Err enviando el mail: %s", err)
	}
	return nil
}
