#!/usr/bin/env python3

import boto3
import argparse
import logging
import os # Import os to potentially get region from environment as a fallback

# --- Configuration ---
# Set the target AWS region here.
# Set to None to use the default region configured in your AWS environment
# (e.g., AWS_DEFAULT_REGION environment variable, or ~/.aws/config).
# Example: TARGET_REGION = 'us-east-1'
TARGET_REGION = None
# --- End Configuration ---


# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def list_instances(filter_running, region=None):
    """
    Lists EC2 instance names and private IP addresses, optionally filtering for running instances
    and specifying a region.

    Args:
        filter_running (bool): If True, only lists instances in the 'running' state.
        region (str, optional): The AWS region to target. If None, uses the default
                                region from the AWS configuration.

    Returns:
        None: Prints the instance information to the console.
    """
    try:
        # Initialize the EC2 client using the specified or default region
        session = boto3.Session(region_name=region)
        ec2_client = session.client('ec2')
        # Determine the actual region being used (either specified or default)
        actual_region = ec2_client.meta.region_name
        logger.info(f"Targeting AWS region: {actual_region}")

        # Define filters
        filters = []
        if filter_running:
            filters.append({
                'Name': 'instance-state-name',
                'Values': ['running']
            })
            logger.info("Filtering for running instances only.")
        else:
            logger.info("Listing all instances regardless of state.")

        # Describe instances using the specified filters and pagination
        paginator = ec2_client.get_paginator('describe_instances')
        page_iterator = paginator.paginate(Filters=filters)

        instance_count = 0
        print(f"\n--- Instances in region: {actual_region} ---") # Header for clarity
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
                print(f"\nNo running instances found in {actual_region} matching the criteria.")
            else:
                print(f"\nNo instances found in {actual_region}.")
        else:
             print(f"\nFound {instance_count} instance(s) in {actual_region}.")


    except boto3.exceptions.NoCredentialsError:
        logger.error("AWS credentials not found. Configure credentials (e.g., environment variables, ~/.aws/credentials, IAM role).")
    except boto3.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'AuthFailure' or error_code == 'UnrecognizedClientException':
             # Use actual_region in error message if available, otherwise fallback
             region_name_for_error = region if region else "default"
             logger.error(f"AWS authentication/authorization error in region {region_name_for_error}: {e}. Check credentials and permissions.")
        elif 'InvalidParameterValue' in str(e) and 'region' in str(e).lower():
             logger.error(f"Invalid AWS region specified: '{region}'. Please check the region name in the TARGET_REGION variable.")
        else:
            region_name_for_error = region if region else "default"
            logger.error(f"An AWS client error occurred in region {region_name_for_error}: {e}")
    except boto3.exceptions.Boto3Error as e:
        logger.error(f"A Boto3 error occurred: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Set up argument parser (only for the running filter now)
    parser = argparse.ArgumentParser(description='List EC2 instance names and private IPs.')
    parser.add_argument(
        '-r',                   # Short version of the argument
        '--running-only',       # Long version of the argument
        action='store_true',    # Makes it a flag; stores True if present, False otherwise
        help='Only list instances that are in the "running" state.'
    )
    # Removed the region argument parser

    # Parse arguments
    args = parser.parse_args()

    # Call the function, passing the global TARGET_REGION variable
    logger.info("Fetching EC2 instance information...")
    # Pass the global variable TARGET_REGION to the function
    list_instances(args.running_only, TARGET_REGION)
    logger.info("Script finished.")
