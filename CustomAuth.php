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

    public $delay = 0.3;
    public $banned = true;
    public $auth;

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

            $IPIsBanned = $this->isBanned($userIP);

            if ($IPIsBanned) {

                $timeout = (new Query())
                    ->select(['reset_at'])
                    ->from('tbl_failed_logins')
                    ->where(['ip' => $userIP])
                    ->one();

                $this->bannedMessage($timeout['reset_at']);
            }

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



    //add first attempt record

    private function select($arrFields = [], $table, $field, $fieldParam, $fieldValueParam)
    {
        $connectDb = Yii::$app->db;
        $fields = implode(", ", $arrFields);
        $query = "SELECT $fields'$table' WHERE '$field' =$fieldParam";
        $sql = $connectDb->createCommand($query);
        return $sql->bindParam($fieldParam, $fieldValueParam);
    }


    //isBanned function

    public function update($table, $fields = [], $condition = [])
    {
        $connectDb = Yii::$app->db;
        $sql = $connectDb->createCommand()->update($table, $fields, $condition);
        $sql->execute();
    }




    public function isBanned($userIP)
    {

        $getAttemptFromDb = (new Query())
            ->select(['attempted', 'reset_at'])
            ->from('tbl_failed_logins')
            ->where(['ip' => $userIP])
            ->one();



        if ($getAttemptFromDb['attempted'] == 3) {

            $timeNow = strtotime("now");

            if ($getAttemptFromDb['reset_at'] != NULL) {

                if ($getAttemptFromDb['reset_at'] > $timeNow) {

                    //if reset_at not null and still larger current timestamp, it is still banned.
                    return true;
                }

                if ($getAttemptFromDb['reset_at'] < $timeNow) {
                    $this->removeEntry($userIP);
                }
            }

        }
        //not banned
        return false;

    }

    public function removeEntry($userIP)
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

    public function delete($table, $id )
    {

        $connectDb = Yii::$app->db;
        $sql = $connectDb->createCommand()->delete($table, $id);
        $sql->execute();
    }


    //update an attempted failed login

    public function loginSuccessfull($userIP)
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

    public function insert($table, $fields = [])
    {
        $connectDb = Yii::$app->db;
        $sql = $connectDb->createCommand()->insert($table, $fields);
        $sql->execute();
    }


    public function banIP($userIP)
    {

        $timeWillBeAbleToLogInAgain = strtotime("now") + ($this->delay * 60); //time now + specified delay in seconds

        $this->update('tbl_failed_logins', ['reset_at' => $timeWillBeAbleToLogInAgain,], ['ip' => $userIP]);
        $connection = Yii::$app->getDb();

        /*$connection->createCommand()->insert('tbl_failed_logins', [
            'reset_at' => $timeWillBeAbleToLogInAgain,
            'ip' => $userIP,
        ])->execute();*/

    }


    /**
     * @param $response
     * @throws UnauthorizedHttpException
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

       $remainingAttempts = 3-$attempts['attempted'];

        throw new UnauthorizedHttpException('Your request was made with invalid credentials. your IP will be locked out after 3 attempts. you have '.$remainingAttempts.' attempts remaining');
    }


    //update an attempted failed login

    public function updateAttempted($userIP)
    {
                    $query = new Query;
                    $query->select(['attempted','reset_at'])
                        ->from('tbl_failed_logins')
                        ->where('ip=:ip', [':ip' => $userIP])
                    ->one();


            // build and execute the query
        $getAttemptFromDb = $query->one();

        if ($getAttemptFromDb['attempted'] < 3 || $getAttemptFromDb['attempted'] == NULL) {

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


    public function bannedMessage($timeout)
    {
        $timeoutRemaining = ($timeout - strtotime("now")) / 60;
        $message = 'Sorry, your IP has been blocked for a while due to 3  unsuccessful login attempts. Please try again after ' . $timeoutRemaining . ' minutes.';
        throw new UnauthorizedHttpException($message);
    }


}
