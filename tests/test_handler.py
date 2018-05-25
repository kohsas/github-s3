import unittest
import index


class TestHandlerCase(unittest.TestCase):

    def test_response(self):
        print("testing response.")
        result = index.handler(
            {"headers":{
                "Request URL":" https",
                "X-GitHub-Delivery":" b08e6ce8-5ea5-11e8-8607-2301863fde29",
                "X-GitHub-Event":" push",
                "X-Hub-Signature":" sha1=c40279d448a496d073e20ef2686bd26d3e87d5af"
             },
             "body" : {"repository":{
                             "id":134572202,
                             "name":"www.sangraha.co.in.deploy"
                             }
             }
            }, None)
        print(result)
        #self.assertEqual(result['statusCode'], 200)
        #self.assertEqual(result['headers']['Content-Type'], 'application/json')
        #self.assertIn('Hello World', result['body'])


if __name__ == '__main__':
    unittest.main()
