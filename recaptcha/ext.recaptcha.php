<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
* ExpressionEngine reCAPTCHA 
*
* Replaces the built-in CAPTCHA on member registration and comment forms
* 
* @package		ExpressionEngine reCAPTCHA
* @author		Brandon Jones
* @link			https://github.com/bhj/ExpressionEngine-reCAPTCHA
* @version		1.1.0
* @license		http://www.opensource.org/licenses/mit-license.php
*/

class Recaptcha_ext
{
	var $name			= 'reCAPTCHA';
	var $version		= '1.1.0';
	var $description	= "Replaces the built-in CAPTCHA on member registration and comment forms";
	var $settings_exist	= 'y';
	var $docs_url		= 'https://github.com/bhj/ExpressionEngine-reCAPTCHA';
	var $settings		= array();


	/**
	 * Constructor
	 */	  
    function __construct($settings='')
    {
	    $this->EE =& get_instance();

        $this->settings = $settings;
    }


	/**
	 *   Create CAPTCHA
	 *
	 * @access	public
	 * @param	void
	 * @return	void
	 */
	public function create_captcha()
	{
		// If settings are empty or wrong, try to fall back to the regular
		// captcha and hope they haven't removed its input field yet
		if ( ! $this->_validate_settings())
		{
			return;
		}

		// Create our 'fake' entry in the captcha table
		$data = array(
			'date' 			=> time(),
			'ip_address'	=> $this->EE->input->ip_address(),
			'word'			=> 'reCAPTCHA'
		);

		$this->EE->db->insert('captcha', $data);

		// Use the AJAX API to create the CAPTCHA, and force a create/replace on
		// each load to ensure that stale (cached) challenges aren't shown
		// @todo use something faster than window.onload, but without jQuery
		$output = <<<PIE
			<script type="text/javascript" src="http://www.google.com/recaptcha/api/js/recaptcha_ajax.js"></script>
			<script type="text/javascript">
				window.onload = function(){
					Recaptcha.create('{$this->settings['public_key']}',
						"recaptcha_container",
						{
							theme:'{$this->settings['theme']}',
							lang:'{$this->settings['language']}'
						}
					);				
				};
			</script>
			<div id="recaptcha_container"/>
PIE;

		$this->EE->extensions->end_script = TRUE;
		
		return $output;
	}


	/**
	 *   Validate CAPTCHA
	 *
	 * @access	public
	 * @param	void
	 * @return	void
	 */
	public function validate_captcha()
	{
		// If settings are obviously wrong, try to fall back to the regular
		// captcha and hope they haven't already removed its input field
		if ($this->_validate_settings() !== TRUE)
		{
			return;
		}

		// Stock recaptcha PHP library (v1.11 as of this writing)
		require_once('recaptchalib/recaptchalib.php');

		// Check answer
		$response = recaptcha_check_answer($this->settings['private_key'],
			$this->EE->input->ip_address(),
			$this->EE->input->post('recaptcha_challenge_field'),
			$this->EE->input->post('recaptcha_response_field')
		);
		
		if ($response->is_valid === TRUE)
		{
			// Give EE what it's looking for
			$_POST['captcha'] = 'reCAPTCHA';

			return;
		}

		// Ensure EE knows the captcha was invalid
		$_POST['captcha'] = '';

		// Whether the user's response was empty or just wrong, all we can do is make EE
		// think the captcha is missing, so we'll use more generic language for an error
		$this->EE->lang->loadfile('recaptcha');
		$this->EE->lang->language['captcha_required'] = lang('recaptcha_error');

		if ($this->settings['debug'] == 'y')
		{
			$this->EE->lang->language['captcha_required'] .= " ({$response->error})";
		} 

		return;
	}


	/**
	 *   Settings
	 *
	 * @access	public
	 * @param	void
	 * @return	array
	 */
	public function settings()
	{
		$settings = array(
			'public_key' 	=>  '',
			'private_key' 	=>  '',
			'language'		=> array('s', array('en' => 'English', 'nl' => 'Dutch', 'fr' => 'French', 'de' => 'German', 'pt' => 'Portuguese', 'ru' => 'Russian', 'es' => 'Spanish', 'tr' => 'Turkish'), 'en'),
			'theme'			=> array('r', array('red' => 'Red', 'white' => 'White', 'blackglass' => 'Blackglass', 'clean' => 'Clean'), 'red'),
			'debug'			=> array('r', array('n' => 'Don\'t Show', 'y' => 'Show'), 'n')
		);

		return $settings;
	}


	/**
	 *   Settings sanity check and prep
	 *
	 * @access	private
	 * @param	void
	 * @return	bool
	 */
	private function _validate_settings()
	{
		// Have we been configured at all?
		if (count($this->settings) < 2)
		{
			return FALSE;
		}

		// Be nice
		$this->settings['public_key'] = trim($this->settings['public_key']);
		$this->settings['private_key'] = trim($this->settings['private_key']);
			
		// Is either key obviously invalid?
		if (strlen($this->settings['public_key']) != 40 OR strlen($this->settings['private_key']) != 40)
		{
			return FALSE;
		}

		return TRUE;
	}

    
	/**
	 *   Activate extension
	 *
	 * @access	public
	 * @param	void
	 * @return	bool
	 */
	public function activate_extension()
	{
		$this->EE->db->query($this->EE->db->insert_string('exp_extensions',
				array(
					'extension_id' => '',
					'class'        => __CLASS__,
					'method'       => 'create_captcha',
					'hook'         => 'create_captcha_start',
					'settings'     => '',
					'priority'     => 5,
					'version'      => $this->version,
					'enabled'      => 'y'
				)
			)
		);

	    $this->EE->db->query($this->EE->db->insert_string('exp_extensions',
              array(
					'extension_id' => '',
					'class'        => __CLASS__,
					'method'       => 'validate_captcha',
					'hook'         => 'member_member_register_start',
					'settings'     => '',
					'priority'     => 1,
					'version'      => $this->version,
					'enabled'      => 'y'
				)
			)
		);

	    $this->EE->db->query($this->EE->db->insert_string('exp_extensions',
              array(
					'extension_id' => '',
					'class'        => __CLASS__,
					'method'       => 'validate_captcha',
					'hook'         => 'insert_comment_start',
					'settings'     => '',
					'priority'     => 1,
					'version'      => $this->version,
					'enabled'      => 'y'
				)
			)
		);
	}

	
	/**
	 *   Update extension
	 *
	 * @access	public
	 * @param	string
	 * @return	bool
	 */
	public function update_extension($current = '')
	{
		return TRUE;
	}


	/**
	 *   Disable extension
	 *
	 * @access	public
	 * @param	void
	 * @return	void
	 */
	public function disable_extension()
	{
		$this->EE->db->where('class', __CLASS__);
    	$this->EE->db->delete('extensions');
	}
}
// END CLASS

/* End of file ext.recaptcha.php */
/* Location: ./system/expressionengine/third_party/recaptcha/ext.recaptcha.php */