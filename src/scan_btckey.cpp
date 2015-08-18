/**
 * A simple regex finder.
 */

#include "config.h"
#include "be13_api/bulk_extractor_i.h"
#include "histogram.h"

#include "bulk_extractor.h" // for regex_list type
#include "findopts.h"

#include <string>

using namespace std;

string key[] = {"xprv[a-km-zA-HJ-NP-Z1-9]{107,108}", "xpub[a-km-zA-HJ-NP-Z1-9]{107,108}"};
string lowerCase[] = {"xprv[a-km-z1-9]{107,108}", "xpub[a-km-z1-9]{107,108}"};

namespace { // anonymous namespace hides symbols from other cpp files (like "static" applied to functions)

    regex_list find_list;
    regex_list find_list_lowercase;

    void add_pattern(regex_list &list, const string &pat)
    {
        list.add_regex("(" + pat + ")"); // make a group
    }
    /*
    void add_find_pattern_lowercase(const string &pat)
    {
        find_list_lowercase.add_regex("(" + pat + ")"); // make a group
    }
    */
    void process_find_file(const char *findfile)
    //void process_find_file(ifstream& findfile)
    {
        std::ifstream in;

        in.open(findfile,std::ifstream::in);
        if(!in.good()) {
            err(1,"Cannot open %s",findfile);
        }
        while(!in.eof()){
            std::string line;
            getline(in,line);
            truncate_at(line,'\r');         // remove a '\r' if present
            if(line.size()>0) {
                if(line[0]=='#') continue;  // ignore lines that begin with a comment character
                add_pattern(find_list, line);
            }
        }
    }
}

extern "C"
void scan_btckey(const class scanner_params &sp,const recursion_control_block &rcb)
{
    assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    if(sp.phase==scanner_params::PHASE_STARTUP) {
        assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->name		= "btckey";
        sp.info->author         = "Andrea";
        sp.info->description    = "Simple search for bitcoin key";
        sp.info->scanner_version= "1.0";
        sp.info->flags		= scanner_info::SCANNER_FIND_SCANNER;
        sp.info->feature_names.insert("btckey");
      	sp.info->histogram_defs.insert(histogram_def("btckey","","histogram",HistogramMaker::FLAG_LOWERCASE));
        return;
    }
    if(sp.phase==scanner_params::PHASE_SHUTDOWN) return;

    if (scanner_params::PHASE_INIT == sp.phase) {

        int size = sizeof(key)/sizeof(key[0]);
        for (int i=0; i < size; i++) {
            add_pattern(find_list, key[i]);
        }

        int sizeLower = sizeof(lowerCase)/sizeof(lowerCase[0]);
        for (int i=0; i < sizeLower; i++) {
            add_pattern(find_list_lowercase, lowerCase[i]);
        }

         // process_find_file("/home/andrea/Scrivania/Repo/cryptosleuth/bulk_extractor/src/regex.txt"); //dipende da dove vogliamo avviare lo script bilk_extractor
    }

    if(sp.phase==scanner_params::PHASE_SCAN) {
        /* The current regex library treats \0 as the end of a string.
         * So we make a copy of the current buffer to search that's one bigger, and the copy has a \0 at the end.
         */
        feature_recorder *f = sp.fs.get_name("btckey");

        managed_malloc<u_char> tmpbuf(sp.sbuf.bufsize+1);
        if(!tmpbuf.buf) return;				     // no memory for searching
        memcpy(tmpbuf.buf,sp.sbuf.buf,sp.sbuf.bufsize);
        tmpbuf.buf[sp.sbuf.bufsize]=0;
        for(size_t pos = 0; pos < sp.sbuf.pagesize && pos < sp.sbuf.bufsize;) {
            /* Now see if we can find a string */
            std::string found;
            size_t offset = 0;
            size_t len = 0;
            if(find_list.check((const char *)tmpbuf.buf+pos,&found,&offset,&len) &&
                !find_list_lowercase.check((const char *)tmpbuf.buf+pos,&found,&offset,&len)) {
                if(len == 0) {
                    len+=1;
                    continue;
                }

                std::string found2;
                size_t offset2 = 0;
                size_t len2 = 0;
                size_t part_len = len - 1;

                managed_malloc<u_char> part(part_len);
                if(!part.buf) return;				     // no memory for searching
                memcpy(part.buf, tmpbuf.buf + pos + offset, part_len);
                part.buf[part_len] = 0;

                if (find_list.check((const char *)part.buf, &found2, &offset2, &len2)) {
                    f->write_buf(sp.sbuf, pos + offset + offset2, len2);
                    pos += offset2 + len2;
                } else {
                  f->write_buf(sp.sbuf, pos + offset, len);
                  pos += offset+len;
                }
            } else {
                /* nothing was found; skip past the first \0 and repeat. */
                const u_char *eos = (const u_char *)memchr(tmpbuf.buf+pos,'\000',sp.sbuf.bufsize-pos);
                if(eos) pos=(eos-tmpbuf.buf)+1;		// skip 1 past the \0
                else    pos=sp.sbuf.bufsize;	// skip to the end of the buffer
            }
        }
    }
}
