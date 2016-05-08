<?php
class IPTable {
	public $row = array();
	private $rowptr = 0;
	public function create_row() {
		$this->row[$this->rowptr] = new IPTRow;
		$this->rowptr = $this->rowptr + 1;
	}
	public function get_last_row() {
		return $this->rowptr-1;
	}
}

class IPTRow {
	public $options = array();
	private $optptr = "";
	public function create_option($name) {
		if (array_key_exists($name, $this->options)) {
			if (is_array($this->options[$name])) {
				$temp = new IPTOption();
				array_push($this->options[$name], $temp);
			} else {
				$tempoption = $this->options[$name];
				$this->options[$name] = array();
				$this->options[$name][0] = $tempoption;
			}
		} else {
			$this->options[$name] = new IPTOption();
		}
		$this->optptr = $name;
	}
	public function get_last_option() {
		return $this->optptr;
	}
}

class IPTOption {
	public $values = array();
	private $valptr = 0;
	public function add_value($value) {
		$this->values[$this->valptr] = $value;
		$this->valptr = $this->valptr + 1;
	}
	public function get_last_value() {
		return $this->valptr-1;
	}
}

function parse_table($parameters) {
	$ipt_raw = shell_exec("sudo iptables " . $parameters);
	$ipt_strings = explode("\n",$ipt_raw);
	$iptable_rows = new IPTable();

	foreach ($ipt_strings as $ipt_key => $ipt_value) {
		$iptable_rows->create_row();
		$ipt_substrings = explode(" ",$ipt_value);
		foreach ($ipt_substrings as $ipt_substr_key => $ipt_substr_value) {
			if (substr($ipt_substr_value, 0, 1) === "-") {
				$rownum = $iptable_rows->get_last_row();
				if (substr($ipt_substr_value, 1, 1) === "-") {
					$iptable_rows->row[$rownum]->create_option(substr($ipt_substr_value, 2));
				} else {
					$iptable_rows->row[$rownum]->create_option(substr($ipt_substr_value, 1));
				}
			} else {
				$rownum = $iptable_rows->get_last_row();
				$optname = $iptable_rows->row[$rownum]->get_last_option();
				if ($optname != "") {
					$iptable_rows->row[$rownum]->options[$optname]->add_value($ipt_substr_value);
				} else {
				}
			}
		}
	}
	return $iptable_rows;
}

function print_table($iptable) {
	foreach ($iptable->row as $rownum => $row) {
		if (!is_null($row->options)) {
			if (array_key_exists("P", $row->options)) {
				echo "Default for chain " . $row->options["P"]->values[0] . " is to " . $row->options["P"]->values[1] . " packets.";
			} else {
				if (array_key_exists("A", $row->options)) {
					echo "On chain " . $row->options["A"]->values[0] . " ";
					if (array_key_exists("j", $row->options)) {
						echo $row->options["j"]->values[0] . " packets ";
					}
					if (array_key_exists("p", $row->options)) {
						echo "using protocol " . $row->options["p"]->values[0] . " ";
					}
					if (array_key_exists("i", $row->options)) {
						echo "from interface " . $row->options["i"]->values[0] . " ";
					}
					if (array_key_exists("s", $row->options)) {
						echo "from address " . $row->options["s"]->values[0] . " ";
					}
					if (array_key_exists("o", $row->options)) {
						echo "to interface " . $row->options["o"]->values[0] . " ";
					}
					if (array_key_exists("d", $row->options)) {
						echo "to address " . $row->options["d"]->values[0] . " ";
					}
					if (array_key_exists("sport", $row->options)) {
						echo "from port " . $row->options["sport"]->values[0] . " ";
					}
					if (array_key_exists("dport", $row->options)) {
						echo "targetting port " . $row->options["dport"]->values[0] . " ";
					}
					if (array_key_exists("m", $row->options)) {
						if ($row->options["m"]->values[0] == "limit") {
							echo "with limit of ";
						} else if ($row->options["m"]->values[0] == "comment") {
							echo "with comment ";
						} else {
							echo "matching " . $row->options["m"]->values[0] . " ";
						}
					}
					if (array_key_exists("state", $row->options)) {
						echo $row->options["state"]->values[0] . " ";
					}
					if (array_key_exists("limit", $row->options)) {
						echo $row->options["limit"]->values[0] . " ";
					}
					if (array_key_exists("log-prefix", $row->options)) {
						$tmpimplode = implode($row->options["log-prefix"]->values, " ");
						echo "with log prefix " . $tmpimplode . " ";
					}
					if (array_key_exists("log-level", $row->options)) {
						echo "with log level " . $row->options["log-level"]->values[0];
					}
					if (array_key_exists("to-destination", $row->options)) {
						echo "to NAT desination " . $row->options["to-destination"]->values[0];
					}
				}
		        }
		}
	echo("<br />");
	}
}

echo "Please remember that each rule applies only to packets that have not matched a previous non-default rule.<br />";

$filtertable = parse_table("-S");
$nattable = parse_table("-t nat -S");

echo "<br /><h3>Filter table: </h3>";
print_table($filtertable);

echo "<br /><h3>NAT table: </h3>";
print_table($nattable);

?>

