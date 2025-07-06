import json
import boto3
import os
import pymysql
import time

s3 = boto3.client('s3')
sns = boto3.client('sns')

def lambda_handler(event, context):
    try:
        # Parse the event body
        feedback = json.loads(event['body'])
        student_id = feedback.get('StudentID')
        course_id = feedback.get('CourseID')
        rating = feedback.get('Rating')
        comment = feedback.get('Comment')
        action = feedback.get('action', 'submit')  # Default to 'submit', allow 'query'

        # Validate required fields based on action
        if action == 'submit' and not all([student_id, course_id, rating]):
            return {
                'statusCode': 400,
                'body': json.dumps('Missing required fields: StudentID, CourseID, Rating')
            }

        # Determine RDS host based on action
        if action == 'submit':
            rds_host = os.environ['RDS_HOST']  # Primary for writes
        else:  # 'query' action uses performance replica
            rds_host = os.environ['RDS_REPLICA_HOST_PERFORMANCE']  # Default to performance replica

        # Connect to RDS
        connection = pymysql.connect(
            host=rds_host,
            user=os.environ['RDS_USERNAME'],
            password=os.environ['RDS_PASSWORD'],
            db=os.environ['RDS_DB_NAME'],
            port=int(os.environ['RDS_PORT'])
        )
        with connection.cursor() as cursor:
            if action == 'submit':
                # Store in S3 with StudentID in the key
                bucket_name = os.environ['BUCKET_NAME']
                s3_key = f"feedback/2025/{student_id}_{course_id}_{int(time.time())}.json"
                feedback_data = {
                    'StudentID': student_id,
                    'CourseID': course_id,
                    'Rating': float(rating),
                    'Comment': comment,
                    'Timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                s3.put_object(Bucket=bucket_name, Key=s3_key, Body=json.dumps(feedback_data))

                # Handle schema migration
                cursor.execute("SHOW TABLES LIKE 'FeedbackMetadata'")
                if cursor.fetchone():
                    cursor.execute("DESCRIBE FeedbackMetadata")
                    columns = [row[0] for row in cursor.fetchall()]
                    if 'StudentID' not in columns:
                        cursor.execute("ALTER TABLE FeedbackMetadata DROP PRIMARY KEY")
                        cursor.execute("ALTER TABLE FeedbackMetadata ADD COLUMN StudentID VARCHAR(20)")
                        cursor.execute("ALTER TABLE FeedbackMetadata ADD PRIMARY KEY (StudentID, CourseID)")
                        print("Schema migrated to include StudentID")
                else:
                    cursor.execute("""
                    CREATE TABLE FeedbackMetadata (
                        StudentID VARCHAR(20),
                        CourseID VARCHAR(20),
                        Rating INT,
                        PRIMARY KEY (StudentID, CourseID)
                    )
                    """)
                    print("Table FeedbackMetadata created")

                # Insert or update data
                sql = "INSERT INTO FeedbackMetadata (StudentID, CourseID, Rating) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE Rating = %s"
                cursor.execute(sql, (student_id, course_id, rating, rating))
                connection.commit()

                # Send SNS if low rating
                if float(rating) < 3:
                    sns.publish(TopicArn=os.environ['SNS_TOPIC_ARN'], Message=f"Low rating for {course_id} by {student_id}: {rating}")

                return {
                    'statusCode': 200,
                    'body': json.dumps('Feedback submitted successfully')
                }
            elif action == 'query':
                # Query existing feedback (read operation)
                sql = "SELECT * FROM FeedbackMetadata WHERE StudentID = %s AND CourseID = %s"
                cursor.execute(sql, (student_id, course_id))
                result = cursor.fetchone()
                if result:
                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'StudentID': result[0],
                            'CourseID': result[1],
                            'Rating': result[2]
                        })
                    }
                return {
                    'statusCode': 404,
                    'body': json.dumps('No feedback found')
                }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps('Invalid action')
                }

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error processing feedback: {str(e)}")
        }