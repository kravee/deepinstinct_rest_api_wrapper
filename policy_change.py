#!/opt/homebrew/bin/python3
import requests, logging, os, socket
from datetime import datetime
import json


def script_log(script_dir, log_name, date='20210101'):
    '''
    Create and conf the log file
    :param date:
    :param log_name:
    :param script_dir: base script location
    :return:
    '''
    if not os.path.isdir(str('/'.join([script_dir, 'logs']))):  # If no logs dir, creating log dir
        try:
            os.makedirs(str('/'.join([script_dir, 'logs'])))
            log_file = str(''.join([script_dir, '/', 'logs', '/', log_name, '.log', '_', date]))
        except OSError:
            print("Creation of the directory %s failed, log file will be in the /tmp directory " + str(
                '/'.join([script_dir, 'logs'])))
            log_file = str(''.join(['/tmp/', log_name, '.log']))
    else:
        log_file = str(''.join([script_dir, '/', 'logs', '/', log_name, '.log', '_', date]))

    logging.basicConfig(filename=log_file,
                        format='%(asctime)s %(message)s',
                        filemode='a')
    # Creating an object
    logger = logging.getLogger()
    # Setting the threshold of logger to INFO, DEBUG
    logger.setLevel(logging.INFO)

    return (logger)


def main():
    '''
    The script change all Windows policy for 'dual_use', 'malicious_js_command_execution' to ALLOW
    :return: 0
    '''
    # define DI server config
    script_folder = os.path.dirname(__file__)
    hostname = socket.gethostname()
    today_date = datetime.today().strftime('%Y-%m-%d')
    logger = script_log(script_folder, os.path.basename(__file__).split('.')[0], today_date)
    logger.setLevel(logging.INFO)
    fqdn = 'pov-jp.customers.deepinstinctweb.com'
    key = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTc3NTA5MjgsIm5iZiI6MTY1Nzc1MDkyOCwianRpIjoiMjVhMjA4ODYtYTU3Ni00YmI3LWJiM2MtMWVlNGI0Mzg5NDRkIiwiaWRlbnRpdHkiOnsia2V5Ijo5fSwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.VfMD4Lop5378e1VJW98KbJX5xuKB5y56Yx9w2ygKB4A'
    logger.info("started for appliance %s", fqdn, )
    # get list of policies
    request_url = f'https://{fqdn}/api/v1/policies/'
    headers = {'accept': 'application/json', 'Authorization': key}
    response = requests.get(request_url, headers=headers)
    policies = response.json()

    for policy in policies:
        # for every Windows policy
        if policy['os'] == 'WINDOWS':
            # get policy data from server
            request_url = f'https://{fqdn}/api/v1/policies/{policy["id"]}/data'
            response = requests.get(request_url, headers=headers)
            policy_data = response.json()
            # modify policy data
            for feature in ['dual_use', 'malicious_js_command_execution']:
                if policy_data['data'][feature] in ['DETECT', 'PREVENT']:
                    logger.info('Modifying %s setting from %s to ALLOW for MSP: %s; MSP ID: %s; Policy: %s; Policy '
                                'ID: %s;',
                                feature, str(policy_data['data'][feature]), str(policy['msp_name']),
                                str(policy['msp_id']),
                                str(policy['name']), str(policy['id']), )
                    print("Modifying " + feature + " setting from " + str(policy_data['data'][feature]) \
                          + " to 'ALLOW' for MSP " + str(policy['msp_name']) + " MSP ID: " + str(policy['msp_id']) \
                          + " Policy: " + str(policy['name']) + ", Policy ID " + str(policy['id']))
                policy_data['data'][feature] = 'ALLOW'
                # save modified policy data to server
                response = requests.put(request_url, json=policy_data, headers=headers)
                if response.status_code > 299:
                    logger.info('The modification failed due to %s', response.text, )
                else:
                    logger.info('Modification completed successfully')


if __name__ == "__main__": main()
