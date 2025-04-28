#!/usr/bin/env python3

import boto3
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def list_instances(filter_running):
    """
    Lists EC2 instance names and private IP addresses, optionally filtering for running instances.

    Args:
        filter_running (bool): If True, only lists instances in the 'running' state.

    Returns:
        None: Prints the instance information to the console.
    """
    try:
        # Initialize the EC2 client
        # Assumes credentials are configured (e.g., environment variables, ~/.aws/credentials)
        ec2_client = boto3.client('ec2')

        # Define filters
        filters = []
        if filter_running:
            filters.append({
                'Name': 'instance-state-name',
                'Values': ['running']
            })
            logging.info("Filtering for running instances only.")
        else:
            logging.info("Listing all instances regardless of state.")

        # Describe instances using the specified filters
        # Use pagination for potentially large numbers of instances
        paginator = ec2_client.get_paginator('describe_instances')
        page_iterator = paginator.paginate(Filters=filters)

        instance_count = 0
        # Iterate through pages, reservations, and instances
        for page in page_iterator:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_count += 1
                    instance_id = instance.get('InstanceId', 'N/A')
                    private_ip = instance.get('PrivateIpAddress', 'N/A')
                    instance_state = instance.get('State', {}).get('Name', 'N/A')

                    # Find the 'Name' tag
                    instance_name = 'N/A'
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break

                    print(f"  Name: {instance_name:<25} | Instance ID: {instance_id:<20} | Private IP: {private_ip:<15} | State: {instance_state}")

        if instance_count == 0:
            if filter_running:
                print("\nNo running instances found matching the criteria.")
            else:
                print("\nNo instances found.")
        else:
             print(f"\nFound {instance_count} instance(s).")


    except boto3.exceptions.NoCredentialsError:
        logging.error("AWS credentials not found. Configure credentials (e.g., environment variables, ~/.aws/credentials).")
    except boto3.exceptions.ClientError as e:
        # More specific error handling for AWS API errors
        logging.error(f"An AWS client error occurred: {e}")
    except boto3.exceptions.Boto3Error as e:
        # Catch other Boto3 specific errors
        logging.error(f"A Boto3 error occurred: {e}")
    except Exception as e:
        # Catch any other unexpected errors
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description='List EC2 instance names and private IPs.')
    parser.add_argument(
        '-r',                   # Short version of the argument
        '--running-only',       # Long version of the argument
        action='store_true',    # Makes it a flag; stores True if present, False otherwise
        help='Only list instances that are in the "running" state.'
    )

    # Parse arguments
    args = parser.parse_args()

    # Call the function with the parsed argument
    print("Fetching EC2 instance information...")
    list_instances(args.running_only)
    print("Done.")

