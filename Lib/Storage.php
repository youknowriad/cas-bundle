<?php

namespace Rizeway\Bundle\CasBundle\Lib;

class Storage
{
    /**
     * @var string
     */
    protected $filename;

    /**
     * @param string $filename
     */
    public function __construct($filename)
    {
        $this->filename = $filename;
    }

    /**
     * @param string $pgt
     * @param string $pgtiou
     */
    public function addPgt($pgt, $pgtiou)
    {
        $content = $this->getFileContent();
        $content[] = array('pgt' => $pgt, 'pgtiou' => $pgtiou);
        $this->saveToFile($content);
    }

    /**
     * @param string $pgtiou
     * @return string
     * @throws \Exception
     */
    public function getPgt($pgtiou)
    {
        $content = $this->getFileContent();
        foreach ($content as $key => $row) {
            if ($row['pgtiou'] == $pgtiou) {

                unset($content[$key]);
                $this->saveToFile($content);

                return $row['pgt'];
            }
        }

        throw new \Exception('PGT not found');
    }

    /**
     * @return array
     */
    protected function getFileContent()
    {
        return file_exists($this->filename) ? json_decode(file_get_contents($this->filename), true) : array();
    }

    /**
     * @param $content
     */
    protected function saveToFile($content)
    {
        file_put_contents($this->filename, json_encode($content));
    }
}
