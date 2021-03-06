from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin

import logging
import re

from flexget import plugin
from flexget.event import event
from flexget.plugins.internal.urlrewriting import UrlRewritingError
from flexget.utils.requests import Session, TimedLimiter
from flexget.utils.soup import get_soup

from flexget.entry import Entry
from flexget.utils.search import normalize_unicode


log = logging.getLogger('newpct')

requests = Session()
requests.headers.update({'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'})
requests.add_domain_limiter(TimedLimiter('newpct1.com', '2 seconds'))
requests.add_domain_limiter(TimedLimiter('newpct.com', '2 seconds'))

NEWPCT_TORRENT_FORMAT = 'http://www.newpct.com/torrents/{:0>6}.torrent'
NEWPCT1_TORRENT_FORMAT = 'http://www.newpct1.com/download/{:0>6}.torrent'


class UrlRewriteNewPCT(object):
    """NewPCT urlrewriter and search."""

    schema = {
        'type': 'boolean',
        'default': False
    }

    # urlrewriter API
    def url_rewritable(self, task, entry):
        url = entry['url']
        rewritable_regex = '^http:\/\/(www.)?newpct1?.com\/.*'
        return re.match(rewritable_regex, url) and not url.endswith('.torrent')

    # urlrewriter API
    def url_rewrite(self, task, entry):
        entry['url'] = self.parse_download_page(entry['url'])

    @plugin.internet(log)
    def parse_download_page(self, url):
        if 'newpct1.com' in url:
            log.verbose('Newpct1 URL: %s', url)
            url = url.replace('newpct1.com/', 'newpct1.com/descarga-torrent/')
        else:
            log.verbose('Newpct URL: %s', url)

        try:
            page = requests.get(url)
        except requests.exceptions.RequestException as e:
            raise UrlRewritingError(e)
        try:
            soup = get_soup(page.text)
        except Exception as e:
            raise UrlRewritingError(e)

        torrent_id = None
        if 'newpct1.com' in url:
            url_format = NEWPCT1_TORRENT_FORMAT

            torrent_id_prog = re.compile(r'descargar-torrent/(.+)/')
            match = torrent_id_prog.search(soup.text)
            if match:
                torrent_id = match.group(1)
        else:
            url_format = NEWPCT_TORRENT_FORMAT

            torrent_id_prog = re.compile("(?:parametros\s*=\s*\n?)\s*{\s*\n(?:\s*'\w+'\s*:.*\n)+\s*'(?:torrentID|id)"
                                         "'\s*:\s*'(\d+)'")
            torrent_ids = soup.findAll(text=torrent_id_prog)
            if len(torrent_ids):
                match = torrent_id_prog.search(torrent_ids[0])
                if match:
                    torrent_id = match.group(1)
            if not torrent_id:
                torrent_id_prog = re.compile('function openTorrent.*\n.*\{.*(\n.*)+window\.location\.href =\s*\".*\/(\d+).*\";')
                torrent_ids = soup.findAll(text=torrent_id_prog)
                log.debug('torrent ID not found, searching openTorrent script')
                if torrent_ids:
                    match = torrent_id_prog.search(torrent_ids[0])
                    if match:
                        torrent_id = match.group(2)

        if not torrent_id:
            raise UrlRewritingError('Unable to locate torrent ID from url %s' % url)

        return url_format.format(torrent_id)

    def search(self, task, entry, config=None):
        if not config:
            log.debug('NewPCT disabled')
            return set()
        log.debug('Search NewPCT')
        url_search = 'http://www.newpct1.com/buscar'
        results = set()
        for search_string in entry.get('search_strings', [entry['title']]):
            query = normalize_unicode(search_string)
            query = re.sub(' \(\d\d\d\d\)$', '', query)
            log.debug('Searching NewPCT %s', query)
            query = query.encode('utf8', 'ignore')
            data = {'q': query}
            try:
                response = task.requests.post(url_search, data=data)
            except requests.RequestException as e:
                log.error('Error searching NewPCT: %s', e)
                return results
            content = response.content
            soup = get_soup(content)
            soup2 = soup.find('ul', attrs={'class': 'buscar-list'})
            children = soup2.findAll('a', href=True)
            for child in children:
                entry = Entry()
                entry['url'] = child['href']
                entry_title = child.find('h2')
                if entry_title is None:
                    log.debug('Ignore empty entry')
                    continue
                entry_title = entry_title.text
                if not entry_title:
                    continue
                try:
                    entry_quality_lan = re.search('.+ \[([^\]]+)\](\[[^\]]+\])+$', entry_title).group(1)
                except AttributeError:
                    log.debug('Quality not found')
                    continue
                entry_title = re.sub(' \[.+]$', '', entry_title)
                entry['title'] = entry_title + ' ' + entry_quality_lan
                results.add(entry)
        log.debug('Finish search NewPCT with %d entries', len(results))
        return results

@event('plugin.register')
def register_plugin():
    plugin.register(UrlRewriteNewPCT, 'newpct', interfaces=['urlrewriter', 'search'], api_ver=2)
