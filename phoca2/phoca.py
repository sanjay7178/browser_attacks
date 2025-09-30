import argparse, sys, os, time, concurrent.futures, csv, io
import pickle
from sklearn.ensemble import RandomForestClassifier
from tqdm import tqdm
from pandas import DataFrame, read_csv, concat

sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'probes'))

from timingProbes import *
from featureProbes import *

class Detector:

    timingProbes = [
        tcpSYNTiming,
        tlsClientHelloTiming,
        tlsClientHelloErrorTiming,
        tlsHandshakeTiming,
        httpsGetRequestTiming,
        httpGetRequestTiming,
        httpGetRequestErrorTiming,
        httpsGetRequestErrorTiming,
        httpGetRequestNoHostHeaderTiming,
        httpsGetRequestNoHostHeaderTiming
    ]

    featureProbes = [
        TLSLibrary,
        TLSVersions,
    ]

    def __init__(self, http_port=80, https_port=443, numIterations=10, 
                modelFile="./classifier.cls", rawData=False,
                outputFile=None, outputFormat="csv"):

        self.http_port = http_port
        self.https_port = https_port
        self.numIterations = numIterations
        self.modelFile = modelFile
        self.outputFile = outputFile
        self.outputFormat = outputFormat
        self.rawData = rawData
        self.model = pickle.load(open(self.modelFile, 'rb'))

    def crawl(self, domains):
        crawlResults = {}

        with concurrent.futures.ThreadPoolExecutor(10) as executor:
            for result in self.tqdm_parallel_map(executor, self.testSite, domains):
                crawlResults[result['site']] = {'classification' : result['classification'], 
                                                'data' : result['data']}
                if(self.outputFile == None and not self.rawData):
                    if(len(domains) == 1):
                        print(result['classification'])
                    else:
                        print(f"{result['site']}: {result['classification']}")

        output = self.writeResultsToFile(crawlResults)
        if(output and self.rawData):
            print(output)

    def testSite(self, site):
        result = {'site' : site}
        result['data'] = self.probeSite(site)
        result['classification'] = self.classifySite(result['data'])

        return result

    def classifySite(self, recordings):
        classification = None

        recordingsDataFrame = DataFrame([recordings])
        columnsToDrop = [column for column in recordingsDataFrame if column not in self.model.feature_names]
        recordingsDataFrame = recordingsDataFrame.drop(columnsToDrop, axis=1)
        if(recordingsDataFrame.isna().sum().sum() > 0):
            return classification

        recordingsDataFrame = recordingsDataFrame.reindex(sorted(recordingsDataFrame.columns), axis=1)

        try:
            classification = self.model.predict(recordingsDataFrame)[0]
        except Exception as e:
            print(e)

        return classification

    def probeSite(self, site):
        probeResults = {'site' : site}

        # Place all feature probes into threadpool queue
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        featureProbeThreads = []
        for probe in Detector.featureProbes:
            featureProbeThreads.append(executor.submit(probe(site, self.http_port, self.https_port).test))

        # On the main thread, loop through the timing threads so the main thread does something
        # while the feature threads are running
        for probe in Detector.timingProbes:
            currentProbeResults = probe(site, self.http_port, self.https_port).test(n=self.numIterations)
            probeResults[probe.__name__] = currentProbeResults

        # Compute the additional timing features
        probeResults['httpsGetSynRatio'] = probeResults['httpsGetRequestTiming'] / probeResults['tcpSYNTiming']
        probeResults['httpGetSynRatio'] = probeResults['httpGetRequestTiming'] / probeResults['tcpSYNTiming']
        probeResults['httpsGetErrorSynRatio'] = probeResults['httpsGetRequestErrorTiming'] / probeResults['tcpSYNTiming']
        probeResults['httpGetErrorSynRatio'] = probeResults['httpGetRequestErrorTiming'] / probeResults['tcpSYNTiming']
        probeResults['httpGetHttpGetErrorRatio'] = probeResults['httpGetRequestTiming'] / probeResults['httpGetRequestErrorTiming']
        probeResults['httpsGetHttpsGetErrorRatio'] = probeResults['httpsGetRequestTiming'] / probeResults['httpsGetRequestErrorTiming']

        # Collect the results of the feature threads
        for thread in featureProbeThreads:
            try:
                probeResults.update(thread.result(timeout=60))
            except Exception as e:
                raise e
                probeResults.update({})

        executor.shutdown(wait=False)
        return probeResults

    def writeResultsToFile(self, siteResults):
        if(self.outputFile != None):
            f = open(self.outputFile, 'w')
        else:
            f = io.StringIO()

        if(self.outputFormat == 'csv'):
            resultsToFile = []

            for key,value in siteResults.items():
                currentResults = {}
                if(self.rawData):
                    currentResults.update(value['data'])
                currentResults['classification'] = value['classification']
                currentResults['site'] = key

                resultsToFile.append(currentResults)

            writer = csv.DictWriter(f, fieldnames=resultsToFile[0].keys())
            writer.writeheader()
            for row in resultsToFile:
                writer.writerow(row)
        elif(self.outputFormat == 'json'):
            for key in siteResults.keys():
                if(not self.rawData):
                    del siteResults[key]['data']

            json.dump(siteResults, f)

        if(self.outputFile == None):
            output = f.getvalue()
        else:
            output = None
        f.close()
        return output

    def tqdm_parallel_map(self, executor, fn, *iterables, **kwargs):
        futures_list = []
        results = []
        for iterable in iterables:
            futures_list += [executor.submit(fn, i) for i in iterable]
        if(len(futures_list) > 1 and self.outputFile):
            for f in tqdm(concurrent.futures.as_completed(futures_list), total=len(futures_list), **kwargs):
                yield f.result()
        else:
            for f in concurrent.futures.as_completed(futures_list):
                yield f.result()

def process_args():
    programDescription = """
    ######################################
     _____  _    _  ____   _____
    |  __ \| |  | |/ __ \ / ____|   /\\
    | |__) | |__| | |  | | |       /  \\
    |  ___/|  __  | |  | | |      / /\ \\
    | |    | |  | | |__| | |____ / ____ \\
    |_|    |_|  |_|\____/ \_____/_/    \_\\
    
    ######################################
    """

    parser = argparse.ArgumentParser(description=programDescription, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("domain",
                        nargs="?",
                        help="Domain to classify as a MITM phishing website. Not required if input file specified with -r argument.")
    parser.add_argument("-R", "--raw-data",
                        action="store_true",
                        default=False,
                        help="Record and output raw classification data about site(s).")
    parser.add_argument("-w", "--output-file",
                        type=str,
                        help="File to write probe outputs to. This argument is required if in record mode.",
                        default=None)
    parser.add_argument("-r", "--input-file",
                        type=str,
                        help="File containing URLs or IP addresses to crawl. Each line should contain only the URL.")
    parser.add_argument("-n", "--num-iterations", type=int, default=10,
                        help="Number of times each timing probe should be executed for each site. A larger number of " + \
                                "iterations per site will result in more accurate results, but a longer runtime. " +\
                                "This value defaults to 10.")
    parser.add_argument("--http-port", type=int, default=80,
                        help="Set the port to scan HTTP web servers. Defaults to 80.")
    parser.add_argument("--https-port", type=int, default=443,
                        help="Set the port to scan HTTPS web servers. Defaults to 443.")
    parser.add_argument("--output-format", help="Format to produce output if in \"Record\" mode. Options include: csv, json. Default format is csv.", default="csv")
    args = vars(parser.parse_args())

    if(args["domain"] == None and args["input_file"] == None):
        parser.print_help(sys.stderr)
        sys.exit(1)
    elif(os.geteuid() != 0):
        print("Root permissions not granted. Removing TCP SYN/ACK timing from probe list. Rerun program as root to enable this probe.")
        self.timingProbes.remove(tcpSYNTiming)
    return args

if(__name__ == '__main__'):
    args = process_args()

    if(args['input_file'] != None):
        with open(args['input_file'], "r") as f:
            domains = [domain.strip() for domain in f.readlines()]
    else:
        domains = [args["domain"]]

    detector = Detector(http_port=args['http_port'], 
                        https_port=args['https_port'], 
                        numIterations=args['num_iterations'],
                        rawData=args['raw_data'],
                        outputFile=args['output_file'],
                        outputFormat=args['output_format'])

    detector.crawl(domains)
