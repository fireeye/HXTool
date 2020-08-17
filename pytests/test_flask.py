from hxtool import app, hxtool_run_main, app_init_1, hxtool_global
import unittest

class FlaskSimpleTests(unittest.TestCase):
    
    client = None
    profileName = 'unit_TEST_profile'
    hx_host = '10.61.152.126'
    profile_id = None

    @classmethod
    def setUpClass(cls):
        # Flask initialization
        app.testing = True
        cls.client = app.test_client()
        # special HXTool initialization
        app_init_1(True)
        # clean up any dirt from prior tests
        cls.removeProfile()

    @classmethod
    def tearDownClass(cls):
        cls.removeProfile()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_verifyAccessToHomePage(self):
        assert FlaskSimpleTests.client != None
        response = FlaskSimpleTests.client.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_verifyUnitTestControllerProfileCreate(self):
        FlaskSimpleTests.createProfile()
        self.assertIsNotNone(FlaskSimpleTests.profile_id)

    def test_verifyLogin(self):
        FlaskSimpleTests.createProfile()
        response = FlaskSimpleTests.client.post(
            '/login',
            data=dict(
                ht_user='api_admin', 
                ht_pass='dev3rd25!',
                controllerProfileDropdown=FlaskSimpleTests.profile_id
            ),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)


    @classmethod
    def createProfile(cls):
        if not FlaskSimpleTests.profile_id:
            #create the controller profile for unit testing
            hxtool_global.hxtool_db.profileCreate(
                hx_name=FlaskSimpleTests.profileName,
                hx_host=FlaskSimpleTests.hx_host,
                hx_port='3000')
            cls.profile_id = cls.getProfileId()

    @classmethod
    def removeProfile(cls):
        if hxtool_global.hxtool_db:
            # remove all instances of the unit test profile from the db
            for profile in hxtool_global.hxtool_db.profileList():
                if profile['hx_name'] == cls.profileName:
                    hxtool_global.hxtool_db.profileDelete(profile_id=profile['profile_id'])

    @classmethod
    # Return the profile_id of our unit test profile
    def getProfileId(cls):
        for profile in hxtool_global.hxtool_db.profileList():
            if profile['hx_name'] == cls.profileName:
                return profile['profile_id']
        return None
