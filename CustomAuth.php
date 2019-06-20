<?php

namespace app\auth;

use Throwable;
use Yii;
use yii\db\Exception;
use yii\db\Query;
use yii\filters\auth\AuthMethod;
use yii\web\IdentityInterface;
use yii\web\Request;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;
use yii\web\User;

class CustomAuth extends AuthMethod
{

    private $delay = 5;
    private $banned = true;
    private $auth;
    private $maxAttempts=3;

    /**
     * Authenticates the current user.
     * @param User $user
     * @param Request $request
     * @param Response $response
     * @return IdentityInterface the authenticated user identity. If authentication information is not provided, null will be returned.
     * @throws UnauthorizedHttpException if authentication information is provided but is invalid.
     * @throws Throwable
     * @throws Exception
     */
    public function authenticate($user, $request, $response)
    {
        list($username, $password) = $request->getAuthCredentials();

        if ($this->auth) {
            if ($username !== null && $password !== null) {
                $identity = $user->getIdentity() ?: call_user_func($this->auth, $username, $password);

                if ($identity === null) {
                    $this->handleFailure($response);
                } elseif ($user->getIdentity(false) !== $identity) {
                    $user->switchIdentity($identity);
                }

                return $identity;
            }
        } elseif ($username !== null) {
            $userIP = Yii::$app->request->userIP;

            $IPIsBanned = $this->isBanned($userIP);  // check if user IP is banned first

            if ($IPIsBanned) {

                $timeout = (new Query())
                    ->select(['reset_at'])
                    ->from('tbl_failed_logins')
                    ->where(['ip' => $userIP])
                    ->one();

                $this->bannedMessage($timeout['reset_at']);
            }


            //not banned continue execution

            $identity = $user->loginByAccessToken($username, get_class($this));
            if ($identity === null) {
                $this->handleFailure($response);
            }

            $this->loginSuccessfull($userIP);

            return $identity;
        }

        $this->handleFailure($response);
        return null;
    }




    //****  login retry ban or allow code ****//


    /**
     * @param array $arrFields
     * @param $table
     * @param $field
     * @param $fieldParam
     * @param $fieldValueParam
     * @return \yii\db\Command
     */
    private function select($arrFields = [], $table, $field, $fieldParam, $fieldValueParam)
    {
        $connectDb = Yii::$app->db;
        $fields = implode(", ", $arrFields);
        $query = "SELECT $fields'$table' WHERE '$field' =$fieldParam";
        $sql = $connectDb->createCommand($query);
        return $sql->bindParam($fieldParam, $fieldValueParam);
    }


    /**
     * @param $table
     * @param array $fields
     * @param array $condition
     * @throws Exception
     */
    private function update($table, $fields = [], $condition = [])
    {
        $connectDb = Yii::$app->db;
        $sql = $connectDb->createCommand()->update($table, $fields, $condition);
        $sql->execute();
    }


    /**
     *
     * checks if userIP is banned
     * @param $userIP
     * @return bool
     * @throws Exception
     */
    private function isBanned($userIP)
    {

        $getAttemptFromDb = (new Query())
            ->select(['attempted', 'reset_at'])
            ->from('tbl_failed_logins')
            ->where(['ip' => $userIP])
            ->one();



        if ($getAttemptFromDb['attempted'] == $this->maxAttempts) {

            $timeNow = strtotime("now");

            if ($getAttemptFromDb['reset_at'] != NULL) {

                if ($getAttemptFromDb['reset_at'] > $timeNow) {

                    //if reset_at not null and still larger current timestamp, it is still banned.
                    return true;
                }

                // banned timeout has expired  remove the IP from the blacklist
                if ($getAttemptFromDb['reset_at'] < $timeNow) {
                    $this->removeEntry($userIP);
                }
            }

        }
        //not banned
        return false;

    }


    /**
     *
     * remove useIP from the blacklist
     * @param $userIP
     * @throws Exception
     */
    private function removeEntry($userIP)
    {


        $getIpId = (new Query())
            ->select(['id'])
            ->from('tbl_failed_logins')
            ->where(['ip' => $userIP])
            ->one();

        $removeEntry = Yii::$app->db->createCommand('DELETE FROM tbl_failed_logins WHERE id=:id');

        $removeEntry->bindParam(':id', $id);
        $id=$getIpId['id'];

        $removeEntry->execute();

    }

    /**
     * @param $table
     * @param $id
     * @throws Exception
     */
    private function delete($table, $id )
    {

        $connectDb = Yii::$app->db;
        $sql = $connectDb->createCommand()->delete($table, $id);
        $sql->execute();
    }


    /**
     *
     * on successful login, if the userIP had an entry in the blacklist, maybe 2 attempts or had exceded the max login attempts
     * but timeout has expired. The entry should be deleted -- kinda like reset to 0 counts
     * @param $userIP
     * @throws Exception
     */
    private function loginSuccessfull($userIP)
    {



        $attemptedLogin = (new Query())
            ->select(['id'])
            ->from('tbl_failed_logins')
            ->where(['ip' => $userIP])
            ->one();

        if ($attemptedLogin != NULL) {

            //ip had a failed login entry remove it.
            $this->removeEntry($userIP);

        } else {

            //not exist, exit
            return;
        }
    }

    /**
     * @param $table
     * @param array $fields
     * @throws Exception
     */
    private function insert($table, $fields = [])
    {
        $connectDb = Yii::$app->db;
        $sql = $connectDb->createCommand()->insert($table, $fields);
        $sql->execute();
    }


    /**
     * bans userIP by updating the userIp record with a timeout stamp
     * @param $userIP
     * @throws Exception
     */
    private function banIP($userIP)
    {

        $timeWillBeAbleToLogInAgain = strtotime("now") + ($this->delay * 60); //time now + specified delay in seconds

        $this->update('tbl_failed_logins', ['reset_at' => $timeWillBeAbleToLogInAgain,], ['ip' => $userIP]);
        $connection = Yii::$app->getDb();


    }


    /**
     * @param $response
     * @throws UnauthorizedHttpException
     * @throws Exception
     * {@inheritdoc}
     */

    public function handleFailure($response)
    {
        $userIP = Yii::$app->request->userIP;

        $this->updateAttempted($userIP);

        $query = new Query;
        $attempts = $query->select(['attempted'])
            ->from('tbl_failed_logins')
            ->where('ip=:ip', [':ip' => $userIP])
            ->one();

        $remainingAttempts = $this->maxAttempts-$attempts['attempted'];

        throw new UnauthorizedHttpException('Your request was made with invalid credentials. your IP will be locked out after '.$this->maxAttempts.' attempts. you have '.$remainingAttempts.' attempts remaining');
    }




    /**
     *
     * updates the attempted count for a specific userIp in the db every time an the userIP unsuccessfully tries to login
     * @param $userIP
     * @throws Exception
     * @throws UnauthorizedHttpException
     */
    private function updateAttempted($userIP)
    {
        $query = new Query;
        $query->select(['attempted','reset_at'])
            ->from('tbl_failed_logins')
            ->where('ip=:ip', [':ip' => $userIP])
            ->one();


        // build and execute the query
        $getAttemptFromDb = $query->one();

        if ($getAttemptFromDb['attempted'] < $this->maxAttempts || $getAttemptFromDb['attempted'] == NULL) {

            $newCount  =$getAttemptFromDb['attempted'] + 1;

            if ($getAttemptFromDb['attempted'] == null)      //ip has no failed login entry
            {

                Yii::$app->db->createCommand()
                    ->insert('tbl_failed_logins', [
                        'ip' => $userIP,
                        'attempted' => $newCount,
                    ])->execute();

            }

            else //ip has an existing failed login entry already
            {
                Yii::$app->db->createCommand()
                    ->update('tbl_failed_logins', ['attempted' => $newCount], ['ip' => $userIP] )
                    ->execute();
            }



        } else {  //three attempts reached ---> ban ip for a period = delay

            $this->banIP($userIP);
            $this->bannedMessage($getAttemptFromDb['reset_at']);


        }


    }


    /**
     * function to be called if the user is on timeout
     * @param $timeout
     * @throws UnauthorizedHttpException
     */
    private function bannedMessage($timeout)
    {
        $timeoutRemaining = ($timeout - strtotime("now")) / 60;
        $message = 'Sorry, your IP has been blocked for a while due to '.$this->maxAttempts .' unsuccessful login attempts. Please try again after ' . $timeoutRemaining . ' minutes.';
        throw new UnauthorizedHttpException($message);
    }


}