import json
import boto3
import os
import time

athena = boto3.client('athena')
sns = boto3.client('sns')

def lambda_handler(event, context):
    try:
        # Extract query parameters
        course_id = event.get('queryStringParameters', {}).get('course', 'ALL')
        query = f"SELECT CourseID, AVG(Rating) as AverageRating FROM feedback WHERE CourseID = '{course_id}' OR '{course_id}' = 'ALL' GROUP BY CourseID"
        
        # Execute Athena query with debugging
        print(f"Executing Athena query: {query}")
        response = athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': 'feedback_db'},
            ResultConfiguration={'OutputLocation': f's3://{os.environ["BUCKET_NAME"]}/query-results/'}
        )
        query_execution_id = response['QueryExecutionId']
        print(f"Query execution ID: {query_execution_id}")

        # Poll for query completion
        while True:
            status = athena.get_query_execution(QueryExecutionId=query_execution_id)['QueryExecution']['Status']['State']
            print(f"Query status: {status}")
            if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                break
            time.sleep(1)

        if status == 'SUCCEEDED':
            # Get query results
            results = athena.get_query_results(QueryExecutionId=query_execution_id)
            rows = [[column['VarCharValue'] for column in row['Data']] for row in results['ResultSet']['Rows'][1:]]  # Skip header
            print(f"Query results: {rows}")
            
            # Format results
            formatted_results = {"results": rows, "course": course_id}
            print(f"Formatted results: {formatted_results}")

            # Send SNS notification if average rating is low (e.g., < 3)
            if rows and float(rows[0][1]) < 3:
                sns.publish(
                    TopicArn=os.environ['SNS_TOPIC_ARN'],
                    Message=f"Low average rating ({rows[0][1]}) for {course_id}"
                )

            return {
                'statusCode': 200,
                'body': json.dumps(formatted_results),
                'headers': {'Content-Type': 'application/json'}
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps(f"Query failed with status: {status}")
            }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error processing query: {str(e)}")
        }